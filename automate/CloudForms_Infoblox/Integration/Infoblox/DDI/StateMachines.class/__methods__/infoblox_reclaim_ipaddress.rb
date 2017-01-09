=begin
 infoblox_reclaim_ipaddress.rb

 Author: Kevin Morey <kevin@redhat.com>

 Description: This method is used to reclaim IP addresses from an Infoblox network

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
  rescue RestClient::ResourceNotFound => resourcenotfound
    log_and_update_message(:info, "record not found: #{resourcenotfound.inspect}")
   return resourcenotfound
  rescue RestClient::BadRequest => badrequest
    raise "Bad request: #{badrequest} url: #{url} or possibly wrong api_version: #{api_version}"
  end
end

begin
  case $evm.root['vmdb_object_type']
  when 'miq_provision'
    @task = $evm.root['miq_provision']
    @vm   = @task.vm
    log_and_update_message(:info, "Provision: #{@task.id} Request: #{@task.miq_request.id} Type:#{@task.type}")
  when 'vm'
    @vm   = $evm.root['vm']
    @task = @vm.miq_provision
  else
    exit MIQ_OK
  end

  network_refs = @task.options.fetch(:infoblox_created_refs, []) rescue []
  log_and_update_message(:info, "infoblox_created_refs: #{network_refs}") unless network_refs.blank?

  if network_refs.blank?
    # if for some reason the network refs were not found try and search for the hosts manually
    @vm.hostnames.each do |host|
      query_network_response = call_infoblox(:get, "record:host?name~=#{host}.")
      unless query_network_response.blank?
        log_and_update_message(:info, "query_network_response: #{query_network_response.inspect}")
        query_network_response.each {|r| network_refs << r['_ref'] }
        log_and_update_message(:info, "network_refs: #{network_refs.inspect}")
      end
    end
  end

  network_refs.each do |nr|
    log_and_update_message(:info, "reclaiming infoblox ref: #{nr}")
    reclaim_ip_response = call_infoblox(:delete, nr)
    log_and_update_message(:info, "reclaim_ip_response: #{reclaim_ip_response.inspect}")
  end

  # Set Ruby rescue behavior
rescue => err
  log_and_update_message(:error, "[#{err}]\n#{err.backtrace.join("\n")}")
  exit MIQ_OK
end
