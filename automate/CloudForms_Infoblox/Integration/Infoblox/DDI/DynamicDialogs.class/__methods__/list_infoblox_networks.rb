=begin
 list_infoblox_networks.rb

 Author: Kevin Morey <kevin@redhat.com>

 Description: This method is used to build a dialog of Infoblox networks

 reference: http://community.infoblox.com/t5/API-Integration/The-definitive-list-of-REST-examples/td-p/1214
-------------------------------------------------------------------------------
   Copyright 2017 Kevin Morey <kevin@redhat.com>

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
    $evm.log(:info, "Calling -> Infoblox:<#{url}> action:<#{action}> payload:<#{params[:payload]}>")
    response = RestClient::Request.new(params).execute
    unless response.code == 200 || response.code == 201
      raise "Failure response:<#{response.code}>"
    else
      $evm.log(:info, "Success response:<#{response.code}>")
    end
    return JSON.parse(response) rescue (return response)
  rescue RestClient::BadRequest => badrequest
    raise "Bad request: #{badrequest} url: #{url} or possibly wrong api_version: #{api_version}"
  end
end

dialog_hash = {}

# need a network_view to filter the available networks
network_view = $evm.object['network_view']

# You can hardwire network CIDRs in the instance if you want to just list specific networks
networks_array = $evm.object['networks']

unless networks_array.blank?
  networks_array.each do |net|
    dialog_hash[net] = "#{net},#{network_view}"
  end
end

if networks_array.blank?
  # get an array of networks from infoblox

  network_search_filter = "network?network_view=#{network_view}"
  # specify fields to return in payload
  return_fields = "&_return_fields=network_view,network,netmask,ipv4addr,extattrs,comment,options"

  networks_array = call_infoblox(:get, "#{network_search_filter}" + "#{return_fields}")
  $evm.log(:info, "Inspecting networks_array: #{networks_array.inspect}")

  networks_array.each do |net|
    comment = "#{net['comment']}@" if net['comment']
    display_string = "#{comment}#{net['network']},#{net['network_view']}"
    dialog_hash[net['network']] = display_string
  end
end

if dialog_hash.blank?
  dialog_hash[''] = "< no networks found, contact administrator >"
  $evm.object['required'] = false
else
  $evm.object['default_value'] = dialog_hash.first
end

$evm.object["values"]     = dialog_hash
$evm.log(:info, "$evm.object['values']: #{$evm.object['values'].inspect}")
