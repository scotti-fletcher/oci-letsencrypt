#require libraries. Note we only import the OCI libraries we use for performance
require 'fdk'
require 'oci/common'
require 'oci/auth/auth'
require 'oci/core/core'
require 'oci/dns/dns'
require 'oci/certificates/certificates'
require 'oci/certificates_management/certificates_management'
require 'oci/loggingingestion/loggingingestion'
require 'oci/functions/functions'
require 'oci/object_storage/object_storage'
require 'oci/vault/vault'
require 'oci/secrets/secrets'
require 'openssl'
require 'acme-client'
require 'open-uri'
require './models'

FN_APP_OCID = ENV['FN_APP_ID']
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
USE_CONFIG = ENV['USE_CONFIG'] == "TRUE"

def get_cert_config
  #get the file from object storage
  object_storage_client = OCI::ObjectStorage::ObjectStorageClient.new(signer: get_signer)
  os_namespace = object_storage_client.get_namespace
  begin
    cert_config =
      JSON.parse(object_storage_client.get_object(
        object_storage_client.get_namespace.data,
        'lets-encrypt',
        'config.json',
        http_response_content_type: 'text/json'
      ).data)
  rescue OCI::Errors::ServiceError
    FDK.log(entry: "Config file config.json missing in #{os_namespace}/lets-encrypt/ bucket.")
  end
  cert_config
end

def log_action(message)
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
              data: {log_time: log_time, message: message}.to_json,
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


def run_function(context:, input:)

  #we need to check if the worker function is present as the new version uses this.
  functions_client = OCI::Functions::FunctionsManagementClient.new(signer: get_signer)
  worker = functions_client.list_functions(ENV['FN_APP_ID'], display_name: 'worker').data.first
  if worker.nil?
    FDK.log(entry: 'Worker function missing, please see https://github.com/scotti-fletcher/oci-letsencrypt')
    return 'Worker function missing, please see https://github.com/scotti-fletcher/oci-letsencrypt'
  end

  invoke_client = OCI::Functions::FunctionsInvokeClient.new(signer: get_signer, endpoint: worker.invoke_endpoint)
  if USE_CONFIG
    get_cert_config['certificates'].each do |cert|
      invoke_client.invoke_function(worker.id, invoke_function_body: cert, fn_invoke_type: 'detached')
    end
  else #we build the required JSON object to send
    single_cert = {
      "cn_name": CERT_CN_NAME,
      "alt_names": [],
      "dns_zone_name": DNS_ZONE_NAME,
      "dns_region": DNS_REGION,
      "certificate_region": DNS_REGION,
      "cert_compartment_ocid": COMPARTMENT_ID,
      "auto_deploy": ENV['CERT_AUTO_DEPLOY'] == 'YES',
      "vault_region": DNS_REGION,
      "vault_ocid": OCI_VAULT_ID,
      "vault_master_key_ocid": VAULT_MASTER_KEY_ID,
      "renew_days_before_expiry": RENEW_DAYS_BEFORE_EXPIRY
    }
    invoke_client.invoke_function(worker.id, invoke_function_body: single_cert, fn_invoke_type: 'detached')
  end

end

FDK.handle(target: :run_function)