--
-- Rules for email messages processing in Lua used by Dr.Web MailD 11.1
-- Short MailD Lua API summary (for Rspamd protocol)
--

-- Provided auxiliary modules
local drweb = require "drweb"
  -- Common utilities
     -- drweb.log(level, message)
     -- drweb.debug("this is a debug message")
     -- drweb.info("this is an info message")
     -- drweb.notice("this is an notice message")
     -- drweb.warning("this is a warning message")
     -- drweb.error("this is an error message")
     -- drweb.sleep(time) -- pause execution for time seconds
     -- drweb.async(func) -- async start of specified function

local dns = require "drweb.dnsxl"
  -- Contains functions to check IP (URL) on DNSxL  (SURBL) servers
     -- dns.ip(ip_address, dnsxl_server)
     -- dns.url(url, surbl_server)

local lookup = require "drweb.lookup"
-- Contains function to get data from external storages via LookupD (AD, ldap, ... etc)
     -- lookup.lookup(request, parameters)

-- Entry point to check email message sent to the Dr.Web MailD by Rspamd protocol
function rspamd_hook(ctx)
  -- In Lua, object-oriented programming is implemented using tables.
  -- More about tables you can read here: https://www.lua.org/pil/2.5.html
  -- Argument ctx (RspamdContext) describes the email message to check
  -- ctx provides the following fields:
       -- sender    (table)            -- sender of the message
           -- hostname     (string)
           -- ip           (table)
       -- helo      (string)            -- HELO information
       -- from      (string)            -- sender' email address
       -- to        (array of strings)  -- recipient email addresses
       -- message   (table)             -- email message to check
           -- raw          (string)
           -- spam         (table)
           -- header       (table)
               -- field       (array of tables)
               -- search      (function)
               -- value       (function)
           -- body         (table MimeBody)
               -- raw         (string)
               -- decoded     (string)
               -- text        (string)
               -- scan_report (table)
               -- url         (array of tables)
               -- search      (function)
               -- md5         (string)
               -- sha1        (string)
               -- sha256      (string)
           -- part         (array of tables)
               -- header      (table)
               -- body        (table)
               -- part        (array of tables)
               -- name        (string)
               -- search      (function)
               -- part_at     (function)
               -- files       (function)
               -- parts       (function)
               -- attachments (function)
               -- leaf_parts  (function)
               -- text_parts  (function)
               -- threats     (function)
               -- urls        (function)
               -- has_file    (function)
               -- has_part    (function)
               -- has_threat  (function)
               -- has_url     (function)
           -- name         (string)
           -- search       (function)
           -- part_at      (function)
           -- files        (function)
           -- parts        (function)
           -- attachments  (function)
           -- leaf_parts   (function)
           -- text_parts   (function)
           -- threats      (function)
           -- urls         (function)
           -- has_file     (function)
           -- has_part     (function)
           -- has_threat   (function)
           -- has_url      (function)

  -- Now we can see the information we are interested in about the message.

    -- Output message data to log of Dr.Web MailD on level "notice"
    drweb.notice("SMTP HELO/EHLO: " .. ctx.helo)
    drweb.notice("SMTP MAIL FROM: " .. ctx.from)

    drweb.notice("Sender info:")
    drweb.notice(" -> hostname: " .. ctx.sender.hostname)
    drweb.notice(" -> ip: " .. ctx.sender.ip)

    -- Iterate throw array of recipients
    drweb.notice("Message rcpts:")
    for _, rcpt in ipairs(ctx.to) do
        drweb.notice(" -> " .. rcpt)
    end

    -- If message type is not multipart, output headers and body
    if #ctx.message.part == 0 then
        drweb.notice("Message HEADERS:")
        local headers = ctx.message.header.field
        for i =1, #headers do
            drweb.notice(" -> " .. headers[i].name .. ": " .. headers[i].value)
        end
        drweb.notice("Message BODY:")
        drweb.notice(" -> " .. ctx.message.body.raw)
    -- Else disassemble it in parts
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

  -- Then we can check message for a legit consistence

    -- If the message contains an URL from any of specified categories, reject it (return the score exceed the threshold)
    if ctx.message.has_url{category = {"adult_content", "social_networks"}} then
        return {
        score = 200,
        threshold = 100,
        symbols = {
                {
                    name = "The message contains unwanted URL(s)",
                    score = 200
                }
            }
        }
    end

    -- If the message contains any threats, reject it (return the score exceed the threshold)
    if ctx.message.has_threat() then
        return {
        score = 900,
        threshold = 100,
        symbols = {
                {
                    name = "The message contains threat(s)",
                    score = 900
                }
            }
        }
    end

    -- Check the message for spam and reject it, if spam score is exceed 100 (return the score exceed the threshold)
    if ctx.message.spam.score > 100 then
        return {
            score = ctx.message.spam.score,
            threshold = 100,
            symbols = {
                {
                    name = "The message was recognized as spam",
                    score = ctx.message.spam.score
                }
            }
        }
    end

    -- The hook function must return report to SMTP server.
    -- RspamdResult
        -- score        (integer)
        -- threshold    (integer)
        -- action       (string)
        -- symbols          (array of tables)
            -- name         (string)
            -- score        (integer)
            -- description  (string)
    return {
        score = ctx.message.spam.score,
        threshold = 100,
        symbols = {
                {
                    name = "The message is clean",
                    score = 0
                }
            }
        }

end
