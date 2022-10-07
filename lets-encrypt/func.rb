#require libraries. Note we only imnport the OCI libraries we use for performance
require 'fdk'
require 'oci/common'
require 'oci/auth/auth'
require 'oci/core/core'
require 'oci/dns/dns'
require 'oci/certificates/certificates'
require 'oci/certificates_management/certificates_management'
require 'oci/loggingingestion/loggingingestion'
require 'oci/functions/functions'
require 'oci/vault/vault'
require 'oci/secrets/secrets'
require 'openssl'
require 'acme-client'
require 'open-uri'
require './models'



LE_ENDPOINT_URI = ENV['LETS_ENCRYPT_URI']
CERT_CONTACT = ENV['CERT_CONTACT']
DNS_ZONE_NAME = ENV['DNS_ZONE_NAME']
DNS_REGION = ENV['DNS_REGION']
CERT_CN_NAME = ENV['CERT_CN_NAME']
COMPARTMENT_ID = ENV['CERT_COMPARTMENT_OCID']
CERT_AUTO_DEPLOY = ENV['CERT_AUTO_DEPLOY'] == 'YES'
OCI_LOG_ID = ENV['OCI_LOG_OCID']
OCI_VAULT_ID = ENV['OCI_VAULT_OCID']
VAULT_SECRET_NAME = ENV['VAULT_SECRET_NAME']
VAULT_MASTER_KEY_ID = ENV['VAULT_MASTER_KEY_OCID']
RENEW_DAYS_BEFORE_EXPIRY = ENV['RENEW_BEFORE_EXPIRY_DAYS'].to_i


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

#gets the Let's Encrypt account key from the vault
def get_lets_encrypt_acc_key
  vault_client = OCI::Vault::VaultsClient.new(signer: get_signer)
  vault_secrets = []
  vault_client.list_secrets(COMPARTMENT_ID).data.each do |resp|
    vault_secrets << resp
  end
  cert_bot_secret = vault_secrets.select{|vs| vs.secret_name == VAULT_SECRET_NAME}.first
  return nil if cert_bot_secret.nil?
  secret_client = OCI::Secrets::SecretsClient.new(signer: get_signer)
  acc_key_secret = secret_client.get_secret_bundle(cert_bot_secret.id, stage: 'CURRENT').data
  return OpenSSL::PKey::RSA.new(Base64.decode64(acc_key_secret.secret_bundle_content.content))
end

#Adds the Let's Encrypt account key to the vault
def add_lets_encrypt_acc_key(acc_private_key)
  vault_client = OCI::Vault::VaultsClient.new(signer: get_signer)
  vault_client.create_secret(
    OCI::Vault::Models::CreateSecretDetails.new(
      compartment_id: COMPARTMENT_ID,
      secret_content:
        OCI::Vault::Models::Base64SecretContentDetails.new(
          name: Time.now.to_i,
          stage: 'CURRENT',
          content: Base64.encode64(acc_private_key.to_s)
        ),
      secret_name: VAULT_SECRET_NAME,
      vault_id: OCI_VAULT_ID,
      description: 'Account Key for Lets Encrypt ACME',
      key_id: VAULT_MASTER_KEY_ID
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
def update_dns(challenge)
  dns_client = OCI::Dns::DnsClient.new(signer: get_signer, region: DNS_REGION)
  dns_zone = []
  dns_client.get_zone_records(DNS_ZONE_NAME).each do |resp|
    dns_zone  += resp.data.items
  end

  records_to_update = []
  existing_zone = dns_zone.select{|r| r.domain == "#{challenge.record_name}.#{CERT_CN_NAME}"}.first

  if !existing_zone.nil?
    records_to_update << OCI::Dns::Models::RecordOperation.new(operation: 'REMOVE',
                                                               domain: "#{challenge.record_name}.#{CERT_CN_NAME}")
  end
  records_to_update << OCI::Dns::Models::RecordOperation.new(operation: 'ADD',
                                                             domain: "#{challenge.record_name}.#{CERT_CN_NAME}",
                                                             rdata: challenge.record_content,
                                                             rtype: challenge.record_type,
                                                             ttl: 30)
  zone_update = OCI::Dns::Models::PatchDomainRecordsDetails.new(items: records_to_update)
  dns_client.patch_domain_records(DNS_ZONE_NAME, "#{challenge.record_name}.#{CERT_CN_NAME}", zone_update)
end

#create keys, and request cert from Let's Encrypt
def exec_cert_bot(existing_cert)

  acc_private_key = get_lets_encrypt_acc_key
  if acc_private_key.nil?
    acc_private_key = OpenSSL::PKey::RSA.new(4096)
    add_lets_encrypt_acc_key(acc_private_key)
  end

  client = Acme::Client.new(private_key: acc_private_key, directory: LE_ENDPOINT_URI)
  account = client.new_account(contact: CERT_CONTACT, terms_of_service_agreed: true)
  account.kid

  order = client.new_order(identifiers: [CERT_CN_NAME])
  authorization = order.authorizations.first
  challenge = authorization.dns
  update_dns(challenge)
  sleep(30) #wait 30 seconds while DNS propagates to prevent premature failure

  challenge.request_validation
  while challenge.status == 'pending'
    sleep(2)
    challenge.reload
  end

  cert_private_key = OpenSSL::PKey::RSA.new(4096)

  csr = Acme::Client::CertificateRequest.new(private_key: cert_private_key, subject: { common_name: CERT_CN_NAME})
  order.finalize(csr: csr)
  while order.status == 'processing'
    sleep(1)
    order.reload
  end

  new_cert = OpenSSL::X509::Certificate.new(order.certificate)
  new_server_cert_chain = retrieve_cert_chain(new_cert).join if has_ca_issuer_uris?(new_cert)


  if existing_cert.nil?
    created_cert = add_cert(new_cert.to_pem, new_server_cert_chain, cert_private_key.to_pem)
    log_action(created_cert, "Creating new cert for #{CERT_CN_NAME} valid to #{new_cert.not_after.strftime('%Y-%m-%d')}")
  else
    update_cert(existing_cert, new_cert.to_pem, new_server_cert_chain, cert_private_key.to_pem)
    log_action(existing_cert, "Updating cert #{CERT_CN_NAME} valid to #{new_cert.not_after.strftime('%Y-%m-%d')}")
  end
  "Completed Successfully"
end


#update the existing cert, with a new cert version
def update_cert(certificate, server_cert, server_cert_chain, private_key)
  cert_client = OCI::CertificatesManagement::CertificatesManagementClient.new(signer: get_signer)
  cert_client.update_certificate(
    certificate.id,
    OCI::CertificatesManagement::Models::UpdateCertificateDetails.new(
      description: "Let's Encrypt #{CERT_CN_NAME} certificate",
      certificate_config:
        OCI::CertificatesManagement::Models::UpdateCertificateByImportingConfigDetails
          .new(
            version_name: Time.now.to_i,
            certificate_pem: server_cert,
            cert_chain_pem: server_cert_chain,
            private_key_pem: private_key,
            stage: CERT_AUTO_DEPLOY ? 'CURRENT' : 'PENDING',
            private_key_pem_passphrase: 'thisjustneedstobehere' #this is not used, just needs to be provided to the api
          )
    )
  )
end

#add a new cert
def add_cert(server_cert, server_cert_chain, private_key)
  cert_client = OCI::CertificatesManagement::CertificatesManagementClient.new(signer: get_signer)
  cert = cert_client.create_certificate(
    OCI::CertificatesManagement::Models::CreateCertificateDetails.new(
      name: CERT_CN_NAME,
      description: "Let's Encrypt #{CERT_CN_NAME} certificate",
      compartment_id: COMPARTMENT_ID,
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

def run_function(context:, input:)
  cert_client = OCI::CertificatesManagement::CertificatesManagementClient.new(signer: get_signer)
  cert = cert_client.list_certificates(name: CERT_CN_NAME, compartment_id: COMPARTMENT_ID).data.items.first

  #if we already have a cert, we need to check the latest version and see if it needs renewing
  if !cert.nil?
    latest_cert = cert_client.list_certificate_versions(cert.id, sort_order: 'DESC').data.items.first
    if !(Time.now + (RENEW_DAYS_BEFORE_EXPIRY*86400) > latest_cert.validity.time_of_validity_not_after.to_time)
      return "Nothing to do"
    end
  end

  exec_cert_bot(cert)
end

FDK.handle(target: :run_function)