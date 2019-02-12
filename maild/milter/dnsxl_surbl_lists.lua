-- Auxiliary Dr.Web Lua module providing common utilities
local drweb = require 'drweb'
-- Auxiliary Dr.Web Lua module providing dns checks
local dwxl = require 'drweb.dnsxl'

-- Function checks ip addresses on dnsxl server
local function check_ip(ip, server)
    local log_str = '[' .. ip .. ']'
    local result = dwxl.ip(ip, server)
    -- Return true if ip in blacklist else return false
    if result then
        log_str = 'Bad ip ' .. log_str .. ': '
        for _, record in ipairs(result) do
            log_str = log_str .. record .. ', '
        end
        -- Output message data to log of Dr.Web MailD on level "debug"
        drweb.debug(log_str)
        return true
    else
        log_str = 'Legit ip ' .. log_str
        -- Output message data to log of Dr.Web MailD on level "debug"
        drweb.debug(log_str)
        return false
    end

end

-- Function checks urls on surbl server
local function check_url(url, server)
    local log_str = '[' .. url .. ']'
    local result = dwxl.url(url, server)
    -- Return true if ip in blacklist else return false
    if result then
        log_str = 'Bad ip ' .. log_str .. ': '
        for _, record in ipairs(result) do
            log_str = log_str .. record .. ', '
        end
        -- Output message data to log of Dr.Web MailD on level "debug"
        drweb.debug(log_str)
        return true
    else
        log_str = 'Legit ip ' .. log_str
        -- Output message data to log of Dr.Web MailD on level "debug"
        drweb.debug(log_str)
        return false
    end
end

-- Entry point to check email message sent to the Dr.Web MailD by Rspamd protocol
function milter_hook(ctx)
    local surbl_server = 'multi.surbl.org'
    local dnsxl_server = 'zen.spamhaus.org'

    -- Reject message if sender ip matches the dnsxl server blacklists
    if check_ip(ctx.sender.ip, dnsxl_server) then
        return {action = "reject", message = "Blocked by blacklists of " .. dnsxl_server}
    end
    -- Reject message if sender hostname matches the surbl server blacklists
    if check_url(ctx.sender.hostname, surbl_server) then
        return {action = "reject", message = "Blocked by blacklists of " .. surbl_server}
    end

    return {action = "accept"}
end