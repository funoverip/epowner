description = [[
Gather McAfee ePolicy Orchestrator versions
]]

---
-- @output
-- PORT   STATE SERVICE
-- 443/tcp  open  https
-- | http-epo: McAffe ePolicy Orchestrator server found
-- | Version: 4.6.4
-- | WebConsole available: YES
-- |_reqseckey: available (rogue agent registration possible)
-- 

author = "Jerome Nokin (http://funoverip.net)"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "safe"}

require "nmap"
require "shortport"
require "http"
require "strbuf"

portrule = shortport.port_or_service(443,"https")

action = function(host, port)
	local status = false
	local result
	local epo_version
	local webconsole
	local out

	-- this key is needed to register a rogue agent
	local path_reqseckey = "/Software/Current/EPOAGENT3000/Install/0409/reqseckey.bin"
	-- this file provide epo version
	local path_sitelist  = "/Software/Current/EPOAGENT3000/Install/0409/sitelist.xml"

	local options = {header={}}
    	options['header']['User-Agent'] = "Mozilla/5.0"
	options['redirect_ok'] = false	

	-- Get reqseckey.bin
	result = http.generic_request(host, port, "GET", path_reqseckey , options)
	if(result == nil) then
		return nil
	end
	if result.status ~= 200 then
		return nil
	end
	if result.header["content-type"] ~= "application/octet-stream" then
		return nil
	end

	
	-- get sitelist.xml
	local body  = http.generic_request(host, port, "GET", path_sitelist , options).body
	local regex = pcre.new(" Version=\"([0-9.]+)\" ", 0, "C")	

	-- get version from sitelist.xml
	local s, e, t = regex:exec(body, 0, 0)
	local epo_version = string.sub(body, t[1], t[2])

	-- check if web console is open on default port
	result = ""
        -- result = http.generic_request(host, "8443", "GET", "/help/orionhelp.js" , {redirect_ok = false})
        result = http.generic_request(host, "8443", "GET", "/help/orionhelp.js" , options)
	webconsole = "no "
        if(result ~= nil) then
		if result.status == 200 then
			webconsole = "YES"
                end
        end


	-- out = "FOUND! Version: " .. epo_version .. " WebConsole: " .. webconsole .. " https://" .. host.ip .. path_sitelist
	out = "McAffe ePolicy Orchestrator server found\n"
	out = out .. "Version: " .. epo_version .. "\n"
	out = out .. "WebConsole available on default port: " .. webconsole .. "\n"
	out = out .. "reqseckey: available (rogue agent registration possible)" .. "\n"
	return out
end


