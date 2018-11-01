--
-- Rules for email messages processing in Lua used by Dr.Web MailD 11.1
-- Short MailD Lua API summary (for Milter protocol)
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
-- Contains function to get data from external storages via LookupD (AD, LDAP, ..., etc.)
     -- lookup.lookup(request, parameters)

-- Entry point to check email message sent to the Dr.Web MailD by Milter protocol
function milter_hook(ctx)
  -- In Lua, object-oriented programming is implemented using tables.
  -- More about tables you can read here: https://www.lua.org/pil/2.5.html
  -- Argument ctx (MilterContext) describes the email message to check
  -- ctx provides the following fields:
       -- sender    (table)            -- sender of the message
           -- hostname     (string)
           -- family       (string)
           -- port         (int)
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
       -- modifier  (table)             -- modifications to be applied to the message
           -- add_header_field     (function)
           -- change_header_field  (function)
           -- modifications        (function)
           -- repack               (function)
           -- repack_password      (string)
           -- repack_message       (string)
           -- templates_dir        (string)

  -- Now we can see the information we are interested in about the message.

    -- Output message data to log of Dr.Web MailD on level "notice"
    drweb.notice("SMTP HELO/EHLO: " .. ctx.helo)
    drweb.notice("SMTP MAIL FROM: " .. ctx.from)

    drweb.notice("Sender info:")
    drweb.notice(" -> hostname: " .. ctx.sender.hostname)
    drweb.notice(" -> family: " .. ctx.sender.family)
    drweb.notice(" -> port: " .. ctx.sender.port)
    drweb.notice(" -> ip: " .. ctx.sender.ip)

    -- Iterate through array of recipients
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

    -- If the message contains an URL from any of specified categories, reject it
    if ctx.message.has_url{category = {"adult_content", "social_networks"}} then
        return {action = "reject", message = "Detected url with bad content!"}
    end

    -- If the message contains attachments, check them
    if ctx.message.has_file() then
        -- If attachment extension is .rar, .zip or .7z, accept the message, else reject
        if ctx.message.has_file{name_re = '.*(rar|zip|7z)'} then
            return {action = "accept"}
        else
            return {action = "reject", message = "Only archive (zip|rar|7z) attachments are allowed"}
        end
    end

  -- Then we can analyze and modify ('repack') the message

    -- Set the modifier variable containing the functions for implementing the modifications
    local modifier = ctx.modifier
    -- Set the password for protected archive containing malicious parts of the message
    modifier.repack_password = "qwerty"
    -- Set the text to be added to repacked message
    modifier.repack_message = ""

    -- Place all parts containing threats into the password-protected archive
    for threat, path in ctx.message.threats() do
        modifier.repack(path)
        local msg = " Threat found: " .. threat.name
        modifier.repack_message = modifier.repack_message .. msg
    end

    -- Check the message for spam and modify it, if spam score is exceed 100
    if ctx.message.spam.score > 100 then
        -- Modify value of Subject header
        local old_value = ctx.message.header.value("Subject") or ""
        local new_value = "[SPAM] " .. old_value
        -- Plan to set new value for Subject header
        modifier.change_header_field("Subject", new_value)
        -- Plan to add new header with spam score
        modifier.add_header_field("X-Spam-Score", ctx.message.spam.score)
        modifier.repack_password = "The message was recognized as spam"
        modifier.repack()
    end

  -- The hook function must return response to MTA.
  -- If the response is 'accept' and there are scheduled modifications,
  -- the hook function should return them in order to they are applied.
    return {action = "accept", modifications = modifier.modifications()}

    -- Available responses are:
    -- return {action = "accept"}
    -- return {action = "reject"}
    -- return {action = "discard"}
    -- return {action = "tempfail"}
    -- return {action = "replycode", code = "450", text = "response: Are you serious?"}
end