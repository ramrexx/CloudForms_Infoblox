=begin
 infoblox_acquire_ipaddress.rb

 Author: Kevin Morey <kevin@redhat.com>

 Description: This method is used to acquire next available IP addresses from an Infoblox network

 Usage: You can pass in variables (see below) during provisioning or simply hard-wire 
   settings right on the automate instance or mix and match the settings between the two

  infoblox_nic_0_network=>'10.11.164.0/23',infoblox_nic_0_gateway=>'10.11.165.254',infoblox_nic_0_vlan=>'dvs_vlan164',
  infoblox_nic_1_network=>'192.168.10.0/24', infoblox_nic_1_addr_mode=>'dhcp', infoblox_nic_1_vlan=>'VM Network'

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
  ws_values = @task.options.fetch(:ws_values, {})
  task_nic_options_hash = parse_hash(@task.options).merge(parse_hash(ws_values))
  # no options? initialize first nic
  task_nic_options_hash[0][nil] = nil if task_nic_options_hash.blank?
  log_and_update_message(:info, "Inspecting task_nic_options_hash: #{task_nic_options_hash.inspect}")
  return task_nic_options_hash
end

def generate_unique_macaddress
  case @task.source.vendor
  when 'vmware'
    nic_prefix='00:50:56:'
  when 'redhat'
    nic_prefix='00:1a:4a:'
  end
  # Check up to 50 times for the existence of a randomly generated mac address
  for i in (1..50)
    new_macaddress = "#{nic_prefix}"+"#{("%02X" % rand(0x3F)).downcase}:#{("%02X" % rand(0xFF)).downcase}:#{("%02X" % rand(0xFF)).downcase}"
    log_and_update_message(:info, "Attempt #{i} - Checking for existence of mac_address: #{new_macaddress}")
    return new_macaddress if $evm.vmdb('vm').all.detect {|v| v.mac_addresses.include?(new_macaddress)}.nil?
  end
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

def get_network_view(nic_index, nic_options)
  view = $evm.object['network_view'] || nic_options[:network_view] || 'default'
  log_and_update_message(:info, "nic_index: #{nic_index} view: #{view}")
  return view
end

def get_network(nic_index, nic_options)
  network = $evm.object['network'] || nic_options[:network]
  log_and_update_message(:info, "nic_index: #{nic_index} network: #{network}")
  return network
end

def get_addr_mode(nic_index, nic_options)
  addr_mode = $evm.object['addr_mode'] || nic_options[:addr_mode] || 'static'
  log_and_update_message(:info, "nic_index: #{nic_index} addr_mode: #{addr_mode}")
  return addr_mode
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

def get_subnet_mask(nic_index, nic_options, infoblox_network)
  require 'ipaddress'
  subnet_mask = $evm.object['subnet_mask'] ||
    nic_options[:subnet_mask] ||
    IPAddress(infoblox_network).netmask
  log_and_update_message(:info, "nic_index: #{nic_index} subnet_mask: #{subnet_mask}")
  return subnet_mask
end

def get_gateway(nic_index, nic_options)
  gateway = $evm.object['gateway'] || nic_options[:gateway]
  log_and_update_message(:info, "nic_index: #{nic_index} gateway: #{gateway}")
  return gateway
end

def get_dns_servers(nic_index, nic_options)
  dns_servers = $evm.object['dns_servers'] || nic_options[:dns_servers]
  log_and_update_message(:info, "nic_index: #{nic_index} dns_servers: #{dns_servers}")
  return dns_servers
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

def get_network_devicetype(nic_index, nic_options)
  devicetype = $evm.object['devicetype'] || nic_options[:devicetype]
  # set your own rules here Valid NIC types (depending on vSphere version):
  # ['VirtualE1000','VirtualE1000e','VirtualPCNet32','VirtualVmxnet','VirtualVmxnet3']
  if devicetype.nil?
    if get_operatingsystem(nic_index, @task.source).include?("windows")
      if get_operatingsystem(nic_index, @task.source).include?("2012")
        devicetype = 'VirtualE1000e'
      else
        devicetype = 'VirtualE1000'
      end
    elsif get_operatingsystem(nic_index, @task.source).include?("red hat")
      devicetype = 'VirtualVmxnet3'
    elsif get_operatingsystem(nic_index, @task.source).include?("cent")
      devicetype = 'VirtualVmxnet3'
    else
      devicetype = 'VirtualE1000'
    end
  end
  log_and_update_message(:info, "nic_index: #{nic_index} devicetype: #{devicetype}")
  return devicetype
end

def get_network_vlan(nic_index, nic_options)
  vlan = $evm.object['vlan'] || nic_options[:vlan] ||
    log_and_update_message(:info, "nic_index: #{nic_index} vlan: #{vlan}")
    return vlan
end

def set_task_nic_settings(nic_index, nic_settings)
  @task.set_option(:sysprep_spec_override, 'true') unless boolean(@task.get_option(:sysprep_spec_override))
  @task.set_nic_settings(nic_index, nic_settings)
  log_and_update_message(:info, "Provisioning object updated {:nic_settings => #{@task.options[:nic_settings].inspect}}")
end

def set_task_network_adapter_settings(nic_index, adapter_settings)
  @task.set_network_adapter(nic_index, adapter_settings)
  log_and_update_message(:info, "Provisioning object updated {:networks => #{@task.options[:networks].inspect}}")
end

def set_task_options(nic_index, hostname, fqdn, dns_servers, infoblox_network)
  if nic_index.zero?
    @task.set_option(:dns_servers, dns_servers)
    log_and_update_message(:info, "Provisioning object updated {:dns_servers => #{@task.options[:dns_servers].inspect}}")
    @task.set_option(:vm_target_hostname, hostname)
    log_and_update_message(:info, "Provisioning object updated {:vm_target_hostname => #{@task.options[:vm_target_hostname].inspect}}")
    @task.set_option(:linux_host_name, fqdn)
    log_and_update_message(:info, "Provisioning object updated {:linux_host_name => #{@task.options[:linux_host_name].inspect}}")
  end
  # set a custom attribute on the VM with the nic and network
  custom_attributes_hash = @task.options.fetch(:ws_miq_custom_attributes, {})
  @task.set_option(:ws_miq_custom_attributes, custom_attributes_hash["infoblox_nic_#{nic_index}_network"]=infoblox_network.to_s)
end

begin
  case $evm.root['vmdb_object_type']
  when 'vm'
    @task   = $evm.root['vm'].miq_provision
  when 'miq_provision'
    @task   = $evm.root['miq_provision']
  else
    exit MIQ_OK
  end
  log_and_update_message(:info, "Provision: #{@task.id} Request: #{@task.miq_request.id} Type:#{@task.type}")

  @created_refs = []

  # loop through the task nic options
  get_task_nic_options_hash().each do |nic_index, nic_options|

    # need a network_view to filter the available networks
    infoblox_network_view = get_network_view(nic_index, nic_options)
    network_search_filter = "network?network_view=#{infoblox_network_view}"

    # need a network to search
    infoblox_network = get_network(nic_index, nic_options)
    raise "missing infoblox_network" if infoblox_network.nil?
    network_search_filter += "&network=#{infoblox_network}"

    # specify fields to return in payload
    return_fields = "&_return_fields=network_view,network,netmask,ipv4addr,extattrs,comment,options"

    # get the first element in the network search
    infoblox_network_hash = call_infoblox(:get, "#{network_search_filter}" + "#{return_fields}")[0]
    log_and_update_message(:info, "Inspecting infoblox_network_hash: #{infoblox_network_hash.inspect}")

    hostname = @task.get_option(:vm_target_hostname)
    fqdn = get_fqdn(nic_index, hostname, nic_options)

    # build hash for infoblox
    body_hash = {}
    body_hash[:comment]           = "CloudForms request_id: #{@task.miq_request.id} nic: #{nic_index}"
    body_hash[:name]              = fqdn
    body_hash[:configure_for_dns] = false
    body_hash[:ipv4addrs]         = []

    ipv4addr = {}
    addr_mode = get_addr_mode(nic_index, nic_options)

    if addr_mode == 'dhcp'
      ipv4addr[:configure_for_dhcp] = true
      ipv4addr[:mac]                = generate_unique_macaddress
    else
      ipv4addr[:configure_for_dhcp] = false
    end
    ipv4addr[:ipv4addr]  = "func:nextavailableip:#{infoblox_network},#{infoblox_network_view}"
    body_hash[:ipv4addrs] << ipv4addr

    record_host_response = call_infoblox(:post, 'record:host', body_hash)
    log_and_update_message(:info, "record_host_response: #{record_host_response}")

    # stuff the Infoblox ref into an array so we can easily back out if something goes wrong
    @created_refs << record_host_response
    @task.set_option(:infoblox_created_refs, @created_refs)

    # build nic settings hash
    query_record_host_response = call_infoblox(:get, record_host_response)
    log_and_update_message(:info, "query_record_host_response: #{query_record_host_response}")
    nic_settings = {
      :ip_addr=>query_record_host_response["ipv4addrs"][0]["ipv4addr"],
      :subnet_mask=>get_subnet_mask(nic_index, nic_options, infoblox_network),
      :gateway=>get_gateway(nic_index, nic_options),
      :addr_mode=>addr_mode
    }
    log_and_update_message(:info, "VM: #{hostname} nic: #{nic_index} nic_settings: #{nic_settings}")
    set_task_nic_settings(nic_index, nic_settings)

    # build network_ settings hash
    adapter_settings = {
      :network => get_network_vlan(nic_options, infoblox_network_hash),
      :devicetype => get_network_devicetype(nic_index, nic_options),
      :mac_address => ipv4addr[:mac]
    }
    log_and_update_message(:info, "VM: #{hostname} nic: #{nic_index} adapter_settings: #{adapter_settings}")
    set_task_network_adapter_settings(nic_index, adapter_settings)

    # build task options
    dns_servers = get_dns_servers(nic_index, nic_options)
    set_task_options(nic_index, hostname, fqdn, dns_servers, infoblox_network)
  end

  # Set Ruby rescue behavior
rescue => err
  clean_up_refs
  log_and_update_message(:error, "[#{err}]\n#{err.backtrace.join("\n")}")
  exit MIQ_ABORT
end
