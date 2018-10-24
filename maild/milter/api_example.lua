--
-- Maild 11.1 Lua rules processing
-- Short api summary
--

-- Provided modules
local drweb = require "drweb"           -- common utilities
                                            -- dwreb.log(level, message)
                                            -- dwreb.debug("this is a debugging message")
                                            -- dwreb.info("this is an informational message")
                                            -- dwreb.notice("this is an notice message")
                                            -- dwreb.warning("this is a warning message")
                                            -- dwreb.error("this is an error message")
                                            -- dwreb.sleep(time)
                                            -- dwreb.async(func)
local dns = require "drweb.dnsxl"       -- functions to get access to dnsxl и surbl servers
                                            -- dns.ip(ip_address, dnsxl_server)
                                            -- dns.url(url, surbl_server)
local lookup = require "drweb.lookup"   -- functions to get access to external storages (AD, ldap, ... etc)
                                            -- lookup.lookup(request, parameters)

-- Mandatory function name.
function milter_hook(ctx)
    -- In Lua, object-oriented programming is implemented using tables.
    -- More about table type you can read here: https://www.lua.org/pil/2.5.html
    -- Argument: ctx (MilterContext) message sent to the drweb-maild by Milter protocol
    -- Provide --
    -- ctx ->
            -- sender       (table)
            -- helo         (string)
            -- from         (string)
            -- to           (array)
            -- message      (table)
            -- modifier     (table)

                -- sender ->
                    -- hostname             (string)
                    -- family               (string)
                    -- port                 (int)
                    -- ip                   (table)

                -- message (MimeMessage) ->
                    -- raw                  (string)
                    -- spam                 (table)
                    -- header               (table)             (MimeHeader)
                    -- body                 (table)             (MimeBody)
                    -- part                 (array of tables)   (MimePart)
                    -- name                 (string)
                    -- search               (function)
                    -- part_at              (function)
                    -- files                (function)
                    -- parts                (function)
                    -- attachments          (function)
                    -- leaf_parts           (function)
                    -- text_parts           (function)
                    -- threats              (function)
                    -- urls                 (function)
                    -- has_file             (function)
                    -- has_part             (function)
                    -- has_threat           (function)
                    -- has_url              (function)

                -- modifier ->
                    -- add_header_field     (function)
                    -- change_header_field  (function)
                    -- modifications        (function)
                    -- repack               (function)
                    -- repack_password      (string)
                    -- repack_message       (string)
                    -- templates_dir        (string)

                        -- header (MimeHeader) ->
                            -- field                (array of tables)
                            -- search               (function)
                            -- value                (function)

                        -- body (MimeBody) ->
                            -- raw                  (string)
                            -- decoded              (string)
                            -- text                 (string)
                            -- scan_report          (table)
                            -- url                  (array of tables)
                            -- search               (function)
                            -- md5                  (string)
                            -- sha1                 (string)
                            -- sha256               (string)

                        -- part (MimePart) ->
                            -- header               (table)
                            -- body                 (table)
                            -- part                 (array of tables)
                            -- name                 (string)
                            -- search               (function)
                            -- part_at              (function)
                            -- files                (function)
                            -- parts                (function)
                            -- attachments          (function)
                            -- leaf_parts           (function)
                            -- text_parts           (function)
                            -- threats              (function)
                            -- urls                 (function)
                            -- has_file             (function)
                            -- has_part             (function)
                            -- has_threat           (function)
                            -- has_url              (function)


    --
    -- Now we can see the information we are interested in about the message.

    -- Logging messages in maild.log on level "notice"
    drweb.notice("SMTP HELO/EHLO: " .. ctx.helo)
    drweb.notice("SMTP MAIL FROM: " .. ctx.from)

    drweb.notice("Sender info:")
    drweb.notice(" -> hostname: " .. ctx.sender.hostname)
    drweb.notice(" -> family: " .. ctx.sender.family)
    drweb.notice(" -> port: " .. ctx.sender.port)
    drweb.notice(" -> ip: " .. ctx.sender.ip)

    -- Iterate throw array of rcpts
    drweb.notice("Message rcpts:")
    for _, rcpt in ipairs(ctx.to) do
        drweb.notice(" -> " .. rcpt)
    end

    -- If message type not multipart print headers and body
    if #ctx.message.part == 0 then
        drweb.notice("Message HEADERS:")
        local headers = ctx.message.header.field
        for i =1, #headers do
            drweb.notice(" -> " .. headers[i].name .. ": " .. headers[i].value)
        end
        drweb.notice("Message BODY:")
        drweb.notice(" -> " .. ctx.message.body.raw)
    -- Else disassemble in parts
    else
        drweb.notice("Message parts:")
        for index, part in ipairs(ctx.message.part) do
            drweb.notice("Part " .. index .. " HEADERS:")
            local headers = ctx.message.header.field
            for i =1, #headers do
                drweb.notice(" -> " .. headers[i].name .. ": " .. headers[i].value)
            end
            drweb.notice("Part " .. index .. " BODY:")
            drweb.notice(" -> " .. part.body.raw)
        end
    end

    --
    -- Then we can modificate message

    -- Set the variable modifier, the function for implementing the modifications
    local modifier = ctx.modifier
    -- Set the password on repacked message
    modifier.repack_password = "qwerty"
    -- Set the repacked message
    modifier.repack_message = ""

    -- Place all parts into the password-protected archive where threats was found
    for threat, path in ctx.message.threats() do
        modifier.repack(path)
        local msg = " Threat found: " .. threat.name
        modifier.repack_message = modifier.repack_message .. msg
    end

    -- Check the message for spam and modificate it if the spam points exceed 100
    if ctx.message.spam.score > 100 then
        -- Find Subject header and get it value
        local old_value = ctx.message.header.value("Subject") or ""
        local new_value = "[SPAM] " .. old_value
        -- Modificate Subject at our discretion
        modifier.change_header_field("Subject", new_value)
        -- Add additional header with spamscore
        modifier.add_header_field("X-Spam-Score", ctx.message.spam.score)
    end

    -- Hook must return response to SMTP server
        -- Responses:
    return {action = "accept"}
    -- return {action = "accept"}
    -- return {action = "reject"}
    -- return {action = "discard"}
    -- return {action = "tempfail"}
    -- return {action = "replycode", code = "450", text = "response: are you serious?"}
end
