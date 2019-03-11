-- Auxiliary Dr.Web Lua module providing common utilities
local drweb = require "drweb"

-- Auxiliary Dr.Web Lua module providing regexp checks
local regex = require "drweb.regex"
    -- regex.search(pattern, text [, flags])
    -- regex.match(pattern, text [, flags])

-- Load regexp patterns from files
local whitelist = drweb.load_set("/opt/drweb.com/lists/whitemails.txt")
local blacklist = drweb.load_set("/opt/drweb.com/lists/blackmails.txt")


-- Entry point to check email message sent to the Dr.Web MailD by Rspamd protocol
function milter_hook(ctx)

    -- Stop checks if mail_from matchs one of the patterns loaded from file
    for pattern, _ in pairs(whitelist) do
        if regex.match(pattern, ctx.from, regex.ignore_case) then
            return {action = "accept"}
        end
    end

    -- Stop checks if mail_from matchs one of the patterns loaded from file
    for pattern, _ in pairs(blacklist) do
        if regex.match(pattern, ctx.from, regex.ignore_case) then
            return {action = "reject", message = "Blacklist"}
        end
    end

    return {action = "accept"}
end