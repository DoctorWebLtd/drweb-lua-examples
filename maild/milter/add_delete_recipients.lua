
local drweb = require "drweb"

function milter_hook(ctx)
    -- Redirect the message to special mailbox if it is likely spam
    if ctx.message.spam.score >= 100 then
        drweb.notice("Spam score: " .. ctx.message.spam.score)
        return {action = "accept", added_recipients = {"quarantine@domain.ru"}, deleted_recipients = ctx.to}
    else
        -- Assign X-Drweb-Spam headers in accordance with spam report
        ctx.modifier.add_header_field("X-DrWeb-SpamScore", ctx.message.spam.score)
        ctx.modifier.add_header_field("X-DrWeb-SpamState", ctx.message.spam.type)
        ctx.modifier.add_header_field("X-DrWeb-SpamDetail", ctx.message.spam.reason)
        ctx.modifier.add_header_field("X-DrWeb-SpamVersion", ctx.message.spam.version)
    end
    -- Redirect the message to special mailbox if unwanted URL has been found
    for url in ctx.message.urls{category = {"infection_source", "not_recommended", "owners_notice"}} do
        drweb.notice("URL found: " .. url .. "(" .. url.categories[1] .. ")")
        return {action = "accept", added_recipients = {"quarantine@domain.ru"}, deleted_recipients = ctx.to}
    end
    -- Check if the message contains viruses, set password and repack if so
    for threat, path in ctx.message.threats{category = {"known_virus", "virus_modification", "unknown_virus", "adware", "dialer"}} do
        ctx.modifier.repack_password = "qwerty123"
        ctx.modifier.repack()
        drweb.notice(threat.name .. " found in " .. (ctx.message.part_at(path).name or path))
    end

    -- Accept the message with all scheduled transformations applied
    return {action = 'accept'}
end