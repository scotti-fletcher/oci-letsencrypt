#require libraries. Note we only import the OCI libraries we use for performance
require 'fdk'
require 'oci/common'
require 'oci/auth/auth'
require 'oci/core/core'
require 'oci/dns/dns'
require 'oci/certificates/certificates'
require 'oci/certificates_management/certificates_management'
require 'oci/loggingingestion/loggingingestion'
require 'oci/key_management/key_management'
require 'oci/functions/functions'
require 'oci/object_storage/object_storage'
require 'oci/vault/vault'
require 'oci/secrets/secrets'
require 'openssl'
require 'acme-client'
require 'open-uri'
require './models'

LE_ENDPOINT_URI = ENV['LETS_ENCRYPT_URI']
CERT_CONTACT = ENV['CERT_CONTACT']
OCI_LOG_ID = ENV['OCI_LOG_OCID']
VAULT_SECRET_NAME = ENV['VAULT_SECRET_NAME']


#returns the OCI principal signer, authn & authz of the function in the tenancy
def get_signer
  begin
    session_token = ENV['OCI_RESOURCE_PRINCIPAL_RPST']
    private_key = ENV['OCI_RESOURCE_PRINCIPAL_PRIVATE_PEM']
    private_key_passphrase = ENV['OCI_RESOURCE_PRINCIPAL_PRIVATE_PEM_PASSPHRASE']
    region = ENV['OCI_RESOURCE_PRINCIPAL_REGION']
    return OCI::Auth::Signers::EphemeralResourcePrincipalsSigner.new(
      session_token: session_token,
      private_key: private_key,
      private_key_passphrase: private_key_passphrase,
      region: region
    )
  rescue Exception => e
    FDK.log(entry: e.to_s)
  end
end

def get_vault(cert_config)
  kms_client = OCI::KeyManagement::KmsVaultClient.new(signer: get_signer, region: cert_config['vault_region'])
  kms_client.get_vault(cert_config['vault_ocid'])
end

#gets the Let's Encrypt account key from the vault
def get_lets_encrypt_acc_key(cert_config)
  vault_client = OCI::Vault::VaultsClient.new(signer: get_signer, region: cert_config['vault_region'])
  vault_secrets = []
  vault_client.list_secrets(cert_config['vault_compartment_ocid'], vault_id: cert_config['vault_ocid']).data.each do |resp|
    vault_secrets << resp
  end
  cert_bot_secret = vault_secrets.select{|vs| vs.secret_name == VAULT_SECRET_NAME}.first
  return nil if cert_bot_secret.nil?
  secret_client = OCI::Secrets::SecretsClient.new(signer: get_signer, region: cert_config['vault_region'])
  acc_key_secret = secret_client.get_secret_bundle(cert_bot_secret.id, stage: 'CURRENT').data
  return OpenSSL::PKey::RSA.new(Base64.decode64(acc_key_secret.secret_bundle_content.content))
end

#Adds the Let's Encrypt account key to the vault
def add_lets_encrypt_acc_key(cert_config, acc_private_key)
  vault_client = OCI::Vault::VaultsClient.new(signer: get_signer, region: cert_config['vault_region'])
  vault_client.create_secret(
    OCI::Vault::Models::CreateSecretDetails.new(
      compartment_id: cert_config['vault_compartment_ocid'],
      secret_content:
        OCI::Vault::Models::Base64SecretContentDetails.new(
          name: Time.now.to_i,
          stage: 'CURRENT',
          content: Base64.encode64(acc_private_key.to_s)
        ),
      secret_name: VAULT_SECRET_NAME,
      vault_id: cert_config['vault_ocid'],
      description: 'Account Key for Lets Encrypt ACME',
      key_id: cert_config['vault_master_key_ocid']
    )
  )
end

#recursively retrieve the certs from the cert chain from the issued cert
def retrieve_cert_chain(cert, chain = [])
  new_cert = nil
  URI.open(ca_issuer_uri(cert), "rb") do |ca_cert|
    new_cert = OpenSSL::X509::Certificate.new(ca_cert.read)
    chain << new_cert.to_pem
  end
  retrieve_cert_chain(new_cert, chain) if has_ca_issuer_uris?(new_cert)
  chain
end

def has_ca_issuer_uris?(cert)
  cert_ext = cert.extensions.select{|ex| ex.oid == 'authorityInfoAccess'}.first
  !cert_ext.nil?
end

def ca_issuer_uri(cert)
  cert_ext = cert.extensions.select{|ex| ex.oid == 'authorityInfoAccess'}.first
  cert_ext.to_s.match(/ca\s+issuers\s+-\s+uri:(.+)\b/i)[1]
end

#update DNS zone with the LE challenge value
def update_dns(cert_config, cn_name, challenge)
  dns_client = OCI::Dns::DnsClient.new(signer: get_signer, region: cert_config['dns_region'])
  dns_zone = []
  dns_client.get_zone_records(cert_config['dns_zone_name']).each do |resp|
    dns_zone  += resp.data.items
  end

  records_to_update = []
  existing_zone = dns_zone.select{|r| r.domain == "#{challenge.record_name}.#{cn_name.start_with?('*.') ? cn_name[2..-1] : cn_name}"}.first

  if !existing_zone.nil?
    records_to_update << OCI::Dns::Models::RecordOperation.new(operation: 'REMOVE',
                                                               domain: "#{challenge.record_name}.#{cn_name.start_with?('*.') ? cn_name[2..-1] : cn_name}")
  end
  records_to_update << OCI::Dns::Models::RecordOperation.new(operation: 'ADD',
                                                             domain: "#{challenge.record_name}.#{cn_name.start_with?('*.') ? cn_name[2..-1] : cn_name}",
                                                             rdata: challenge.record_content,
                                                             rtype: challenge.record_type,
                                                             ttl: 30)
  zone_update = OCI::Dns::Models::PatchDomainRecordsDetails.new(items: records_to_update)
  dns_client.patch_domain_records(cert_config['dns_zone_name'], "#{challenge.record_name}.#{cn_name.start_with?('*.') ? cn_name[2..-1] : cn_name}", zone_update)
end

#create keys, and request cert from Let's Encrypt
def exec_cert_bot(cert_config, existing_cert)

  acc_private_key = get_lets_encrypt_acc_key(cert_config)
  if acc_private_key.nil?
    acc_private_key = OpenSSL::PKey::RSA.new(4096)
    add_lets_encrypt_acc_key(cert_config, acc_private_key)
  end

  client = Acme::Client.new(private_key: acc_private_key, directory: LE_ENDPOINT_URI)
  account = client.new_account(contact: CERT_CONTACT, terms_of_service_agreed: true)
  account.kid

  identifiers = [cert_config['cn_name']] + cert_config['alt_names']
  challenges = []
  order = client.new_order(identifiers: identifiers)
  order.authorizations.each_with_index do |authorization, idx|
     challenge = authorization.dns
     update_dns(cert_config, identifiers[idx], challenge)
     challenges << challenge
  end

  sleep(120) #wait 2 minutes while DNS propagates to prevent premature failure

  challenges.each{|challenge| challenge.request_validation}
  while challenges.map{|challenge| challenge.status}.include?('pending')
    sleep(4)
    challenges.each{|challenge| challenge.reload}
  end

  if challenges.map{|challenge| challenge.status}.include?('invalid')
    FDK.log(entry: "One or more DNS challenges failed for #{cert_config['cn_name']}")
  end

  cert_private_key = OpenSSL::PKey::RSA.new(4096)
  csr = Acme::Client::CertificateRequest.new(private_key: cert_private_key, subject: { common_name: cert_config['cn_name']},  names: cert_config['alt_names'])
  order.finalize(csr: csr)
  while order.status == 'processing'
    sleep(1)
    order.reload
  end


  new_cert = OpenSSL::X509::Certificate.new(order.certificate)
  new_server_cert_chain = retrieve_cert_chain(new_cert).join if has_ca_issuer_uris?(new_cert)

  if existing_cert.nil?
    created_cert = add_cert(cert_config, new_cert.to_pem, new_server_cert_chain, cert_private_key.to_pem)
    log_action(created_cert, "Creating new cert for #{cert_config['cn_name']} valid to #{new_cert.not_after.strftime('%Y-%m-%d')}")
  else
    update_cert(cert_config, existing_cert, new_cert.to_pem, new_server_cert_chain, cert_private_key.to_pem)
    log_action(existing_cert, "Updating cert #{cert_config['cn_name']} valid to #{new_cert.not_after.strftime('%Y-%m-%d')}")
  end
  "Completed Successfully"
end


#update the existing cert, with a new cert version
def update_cert(cert_config, certificate, server_cert, server_cert_chain, private_key)
  cert_client = OCI::CertificatesManagement::CertificatesManagementClient.new(signer: get_signer, region: cert_config['certificate_region'])
  cert_client.update_certificate(
    certificate.id,
    OCI::CertificatesManagement::Models::UpdateCertificateDetails.new(
      description: "Let's Encrypt #{cert_config['cn_name']} certificate",
      certificate_config:
        OCI::CertificatesManagement::Models::UpdateCertificateByImportingConfigDetails
          .new(
            version_name: Time.now.to_i,
            certificate_pem: server_cert,
            cert_chain_pem: server_cert_chain,
            private_key_pem: private_key,
            stage: cert_config['auto_deploy'] ? 'CURRENT' : 'PENDING',
            private_key_pem_passphrase: 'thisjustneedstobehere' #this is not used, just needs to be provided to the api
          )
    )
  )
end

#add a new cert
def add_cert(cert_config, server_cert, server_cert_chain, private_key)
  cert_client = OCI::CertificatesManagement::CertificatesManagementClient.new(signer: get_signer, region: cert_config['certificate_region'])
  cert = cert_client.create_certificate(
    OCI::CertificatesManagement::Models::CreateCertificateDetails.new(
      name: cert_config['cn_name'].start_with?('*.') ? "wildcard-#{cert_config['cn_name'][2..-1]}" : cert_config['cn_name'],
      description: "Let's Encrypt #{cert_config['cn_name']} certificate",
      compartment_id: cert_config['cert_compartment_ocid'],
      config_type: 'IMPORTED',
      certificate_config:
        OCI::CertificatesManagement::Models::CreateCertificateByImportingConfigDetails
          .new(
            version_name: Time.now.to_i,
            certificate_pem: server_cert,
            cert_chain_pem: server_cert_chain,
            private_key_pem: private_key,
            private_key_pem_passphrase: 'thisjustneedstobehere' #this is not used, just needs to be provided to the api
          )
    )
  )
  cert.data
end

def log_action(certificate, message)
  log_time = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%S.000Z')
  loggingingestion_client = OCI::Loggingingestion::LoggingClient.new(signer: get_signer)
  loggingingestion_client.put_logs(
    OCI_LOG_ID,
    OCI::Loggingingestion::Models::PutLogsDetails.new(
      specversion: '1.0',
      log_entry_batches: [
        OCI::Loggingingestion::Models::LogEntryBatch.new(
          entries: [
            OCI::Loggingingestion::Models::LogEntry.new(
              data: {log_time: log_time, certificate_ocid: certificate.id, message: message}.to_json,
              id: "ocid1.certbot.oc1..#{SecureRandom.uuid}",
              time: log_time
            )
          ],
          source: 'cert-bot',
          type: 'cert-bot-automation',
          defaultlogentrytime: log_time,
          subject: 'Cert Bot Activity'
        )
      ]
    )
  )
end

#input contains a JSON object of the certificate to renew
def run_function(context:, input:)
  cert_config = input.merge({'vault_compartment_ocid' => get_vault(input).data.compartment_id})

  if cert_config['cn_name'].start_with?('*.') && !cert_config['alt_names'].empty?
    FDK.log(entry: "Certificate #{cert_config['cn_name']} can be only type wildcard or SAN")
    return "Error: Certificate has both wildcard and SAN configured."
  end

  cert_client = OCI::CertificatesManagement::CertificatesManagementClient.new(signer: get_signer, region: cert_config['certificate_region'])
  cert = cert_client.list_certificates(name: cert_config['cn_name'].start_with?('*.') ? "wildcard-#{cert_config['cn_name'][2..-1]}" : cert_config['cn_name'], compartment_id: cert_config['cert_compartment_ocid']).data.items.first

  #if we already have a cert, we need to check the latest version and see if it needs renewing
  if !cert.nil?
    latest_cert = cert_client.list_certificate_versions(cert.id, sort_order: 'DESC').data.items.first
    if !(Time.now + (cert_config['renew_days_before_expiry']*86400) > latest_cert.validity.time_of_validity_not_after.to_time)
      log_action(cert, "Certificate #{cert_config['cn_name']} does not need to be renewed")
      return "Nothing to do"
    end
  end

  exec_cert_bot(cert_config, cert)
end

FDK.handle(target: :run_function)
