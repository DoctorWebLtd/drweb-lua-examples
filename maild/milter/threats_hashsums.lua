-- Auxiliary Dr.Web Lua module providing common utilities
local drweb = require "drweb"

-- Entry point to check email message sent to the Dr.Web MailD by Milter protocol
function milter_hook(ctx)

    -- Set the modifier variable containing the functions for implementing the modifications
    local modifier = ctx.modifier
    -- Set the password for protected archive containing malicious parts of the message
    modifier.repack_password = "qwerty"

    -- array with special threats
    local special_threats_md5_hashes = {
        ["9ecdbee472e6de17ee7aa31f90d12a53"] = true,
        ["bb15b1b3a64782896e0ea61f785675c9"] = true,
        ["17a91b331fd68a5b2fd73747f8da0d62"] = true
    }
    -- Directory to save .eml files
    -- user (drweb-ctl cfshow Maild.RunAsUser) must have write access to that directory
    local special_threats_messages_dir = "/home/user/to_investigate/"

    for threat, path in ctx.message.threats() do
        local threat_body = ctx.message.part_at(path).body
        -- Output message data to log of Dr.Web MailD on level "debug"
        drweb.debug("Threat: " .. threat.name .. " md5_hash: " .. threat_body.md5)
        drweb.debug("Threat: " .. threat.name .. " sha1_hash: " .. threat_body.sha1)
        drweb.debug("Threat: " .. threat.name .. " sha256_hash: " .. threat_body.sha256)
        -- If threat hash matches a hashtable save .eml file and discard message
        if special_threats_md5_hashes[threat_body.md5] then
            drweb.notice("Special threat detected:" .. threat.name .. " md5: " .. threat_body.md5)
            local msg_name = os.date("%Y%m%d_%H%M%S_") .. ctx.from .. ".eml"
            local file = io.open(special_threats_messages_dir .. msg_name, "a")
            file:write(ctx.message.raw)
            file:close()
            return {action = "discard" }
        end
        -- Elsewhere repack message
        modifier.repack(path)
    end

    return {action = "accept"}
end