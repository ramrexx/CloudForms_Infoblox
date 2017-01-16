=begin
 infoblox_recordhost.rb

 Author: Kevin Morey <kevin@redhat.com>

 Description: This method is used to record a host on an Infoblox network. This assumes 
              that the VM has already been assigned an IP address.

 Usage: You can pass in variables (see below) during provisioning or simply hard-wire 
   settings right on the automate instance or mix and match the settings between the two

  infoblox_nic_0_network=>'10.11.164.0/23',infoblox_nic_0_dns_domain=>'example.com',infoblox_nic_1_network=>'192.168.10.0/24'

 reference: http://community.infoblox.com/t5/API-Integration/The-definitive-list-of-REST-examples/td-p/1214
-------------------------------------------------------------------------------
   Copyright 2016 Kevin Morey <kevin@redhat.com>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
-------------------------------------------------------------------------------
=end
def log_and_update_message(level, msg, update_message=false)
  $evm.log(level, "#{msg}")
  @task.message = msg if @task && (update_message || level == 'error')
end

def parse_hash(hash, options_hash=Hash.new { |h, k| h[k] = {} })
  regex = /^infoblox_nic_(\d*)_(.*)/
  hash.each do |key, value|
    if regex =~ key
      nic_index, paramter = $1.to_i, $2.to_sym
      log_and_update_message(:info, "nic_index: #{nic_index} - Adding option: {#{paramter.inspect} => #{value.inspect}} to options_hash")
      options_hash[nic_index][paramter] = value
    end
  end
  options_hash
end

def get_task_nic_options_hash(task_nic_options_hash={})
  return task_nic_options_hash if @task.nil?
  ws_values = @task.options.fetch(:ws_values, {})
  task_nic_options_hash = parse_hash(@task.options).merge(parse_hash(ws_values))
  # no options? initialize first nic
  task_nic_options_hash[0][nil] = nil if task_nic_options_hash.blank?
  log_and_update_message(:info, "Inspecting task_nic_options_hash: #{task_nic_options_hash.inspect}")
  return task_nic_options_hash
end

def call_infoblox(action, ref='network', body_hash=nil)
  require 'rest_client'
  require 'json'

  begin
    servername  = nil || $evm.object['servername']
    username    = nil || $evm.object['username']
    password    = nil || $evm.object.decrypt('password')
    api_version = nil || $evm.object['api_version']
    url = "https://#{servername}/wapi/v#{api_version}/"+"#{ref}"

    params = {
      :method=>action, :url=>url, :verify_ssl=>false,
      :headers=>{ :content_type=>:json, :accept=>:json,
                  :authorization=>"Basic #{Base64.strict_encode64("#{username}:#{password}")}"}
    }
    params[:payload] = JSON.generate(body_hash) if body_hash
    log_and_update_message(:info, "Calling -> Infoblox:<#{url}> action:<#{action}> payload:<#{params[:payload]}>")
    response = RestClient::Request.new(params).execute
    unless response.code == 200 || response.code == 201
      raise "Failure response:<#{response.code}>"
    else
      log_and_update_message(:info, "Success response:<#{response.code}>")
    end
    return JSON.parse(response) rescue (return response)
  rescue RestClient::BadRequest => badrequest
    raise "Bad request: #{badrequest} url: #{url} or possibly wrong api_version: #{api_version}"
  end
end

def get_fqdn(nic_index, hostname, nic_options)
  domain_name = $evm.object['dns_domain'] || nic_options[:dns_domain]
  unless nic_index.zero?
    hostname += "-ext#{nic_index}"
  end
  fqdn = (hostname + '.' + domain_name)
  log_and_update_message(:info, "nic_index: #{nic_index} fqdn: #{fqdn}")
  return fqdn
end

def get_operatingsystem(nic_index, template)
  os = template.try(:operating_system).try(:product_name) ||
    template.try(:hardware).try(:guest_os_full_name) ||
    template.try(:hardware).try(:guest_os) || 'unknown'
  log_and_update_message(:info, "nic_index: #{nic_index} os: #{os}")
  return os.downcase
end

def boolean(string)
  return true if string == true || string =~ (/(true|t|yes|y|1)$/i)
  return false
end

def clean_up_refs
  @created_refs.each do |ref|
    log_and_update_message(:warn, "Cleaning up ref: #{ref}")
    call_infoblox(:delete, ref)
  end
end

def check_ipaddresses
  ip_list = @vm.hardware.ipaddresses rescue []
  log_and_update_message(:info, "IP addresses for VM #{ip_list}")

  if ip_list.blank?
    @vm.refresh
    $evm.root['ae_result'] = 'retry'
    $evm.root['ae_retry_limit'] = 30.seconds
    exit MIQ_OK
    # elsif ip_list.count == 1
    #   @vm.refresh
    #   $evm.root['ae_result'] = 'retry'
    #   $evm.root['ae_retry_limit'] = 15.seconds
    #   exit MIQ_OK
  else
    $evm.root['ae_result'] = 'ok'
  end
end

begin
  case $evm.root['vmdb_object_type']
  when 'miq_provision'
    @task = $evm.root['miq_provision']
    @vm   = @task.vm
  when 'vm'
    @vm   = $evm.root['vm']
    @task = @vm.miq_provision
  else
    exit MIQ_OK
  end
  log_and_update_message(:info, "Provision: #{@task.id} Request: #{@task.miq_request.id} Type:#{@task.type}") if @task

  check_ipaddresses

  @created_refs = []

  # loop through the task nic options
  get_task_nic_options_hash().each do |nic_index, nic_options|

    # pull the ip address from the vm object
    ip_addr = nil
    ip_addr ||= @vm.hardware.ipaddresses.first rescue nil
    # ip_addr ||= @vm.hardware.networks[nic_index]['ipaddress'] rescue nil
    # network = @vm.hardware.networks.detect {|net| net.description=='public'}
    # ip_addr ||= network['ipaddress']

    # pull the hostname from the miq_provision object and set the fqdn
    hostname = @task.get_option(:vm_target_hostname)
    fqdn = get_fqdn(nic_index, hostname, nic_options)

    # build hash for infoblox
    body_hash = {}
    body_hash[:comment]           = "CloudForms request_id: #{@task.miq_request.id} nic: #{nic_index}"
    body_hash[:name]              = fqdn
    body_hash[:configure_for_dns] = true
    body_hash[:ipv4addrs]         = [
      {
        :ipv4addr => ip_addr,
      }
    ]

    record_host_response = call_infoblox(:post, 'record:host', body_hash)
    log_and_update_message(:info, "record_host_response: #{record_host_response}")

    # stuff the Infoblox ref(s) into an array so we can easily back out if something goes wrong
    @created_refs << record_host_response
    @task.set_option(:infoblox_created_refs, @created_refs)

    # stuff the Infoblox ref(s) into a string and display them on the VMs custom attributes
    @vm.custom_set(:infoblox_created_refs, "#{@created_refs.join(",")}")
  end

  # Set Ruby rescue behavior
rescue => err
  clean_up_refs
  log_and_update_message(:error, "[#{err}]\n#{err.backtrace.join("\n")}")
  exit MIQ_ABORT
end
