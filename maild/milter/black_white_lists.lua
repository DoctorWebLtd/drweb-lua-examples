-- Auxiliary Dr.Web Lua module providing common utilities
local drweb = require "drweb"

-- Auxiliary Dr.Web Lua module providing regexp checks
local regex = require "drweb.regex"
    -- regex.search(pattern, text [, flags])
    -- regex.match(pattern, text [, flags])

-- Load regexp patterns from files
local whitelist = drweb.load_array("/opt/drweb.com/lists/whitemails.txt")
local blacklist = drweb.load_array("/opt/drweb.com/lists/blackmails.txt")


-- Entry point to check email message sent to the Dr.Web MailD by Rspamd protocol
function milter_hook(ctx)

    -- Stop checks if mail_from matchs one of the patterns loaded from file
    for _, pattern in ipairs(whitelist) do
        if regex.match(pattern, ctx.from, regex.ignore_case) then
            return {action = "accept"}
        end
    end

    -- Stop checks if mail_from matchs one of the patterns loaded from file
    for _, pattern in ipairs(blacklist) do
        if regex.match(pattern, ctx.from, regex.ignore_case) then
            return {action = "reject", message = "Blacklist"}
        end
    end

    -- regex.match and regex.search can also taking arrays of patterns
    -- and the code above will be pretty simple:

    -- -- Stop checks if mail_from matchs one of the patterns loaded from file
    -- if regex.match(whitelist, ctx.from, regex.ignore_case) then
    --     return {action = "accept" }
    -- end
    -- -- Stop checks if mail_from matchs one of the patterns loaded from file
    -- if regex.match(blacklist, ctx.from, regex.ignore_case) then
    --     return {action = "reject", message = "Blacklist" }
    -- end

    return {action = "accept"}
end