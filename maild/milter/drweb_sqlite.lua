--
-- Auxiliary Dr.Web Lua module providing common utilities
local drweb = require "drweb"
-- Lua module to work with SQLite3 (installed by drweb-luarocks)
sqlite3 = require "lsqlite3"
-- SQLite database file location
local database = '/tmp/drweb.db'

-- Function to add record about a threat to SQLite database
local function db_threat_add(date, host, ip, mail_from, mail_to, threat_name, threat_type)
    local db = sqlite3.open(database)

    local sql_create = "CREATE TABLE IF NOT EXISTS threats (id integer PRIMARY KEY AUTOINCREMENT,\
                                                            date text,\
                                                            host text,\
                                                            ip text,\
                                                            mail_from text,\
                                                            mail_to text,\
                                                            threat_name text,\
                                                            threat_type text);"
    local sql_add = string.format("INSERT INTO threats(date, host, ip, mail_from, mail_to, threat_name, threat_type) values\
    ('%s', '%s', '%s', '%s', '%s', '%s', '%s');", date, host, ip, mail_from, mail_to, threat_name, threat_type)
    local result = assert(db:execute(sql_create))
    -- drweb.notice("SQLite3: create_table result: " .. tostring(result))
    local result = assert(db:execute(sql_add))
    -- drweb.notice("SQLite3: insert_row result: " .. tostring(result))
    db:close()
end

-- Function to add record about spam to SQLite database
local function db_spam_add(date, host, ip, mail_from, mail_to, spam_score)
    local db = sqlite3.open(database)

    local sql_create = "CREATE TABLE IF NOT EXISTS spam (id integer PRIMARY KEY AUTOINCREMENT,\
                                                         date text,\
                                                         host text,\
                                                         ip text,\
                                                         mail_from text,\
                                                         mail_to text,\
                                                         spam_score text);"
    local sql_add = string.format("INSERT INTO spam(date, host, ip, mail_from, mail_to, spam_score) \
    values ('%s', '%s', '%s', '%s', '%s', '%s');", date, host, ip, mail_from, mail_to, spam_score)
    local result = assert(db:execute(sql_create))
    -- drweb.notice("SQLite3: create_table result: " .. tostring(result))
    local result = assert(db:execute(sql_add))
    -- drweb.notice("SQLite3: insert_row result: " .. tostring(result))
    db:close()
end

-- Entry point to check email message sent to the Dr.Web MailD by Milter protocol
function milter_hook(ctx)

    local rcpts = {}

    -- Iterate through array of recipients
    for _, rcpt in ipairs(ctx.to) do
        table.insert(rcpts, rcpt)
    end

    local datetime = os.date()
    local mail_from = ctx.from
    local host = ctx.sender.hostname
    local ip = ctx.sender.ip
    local mail_to = table.concat(rcpts, ", ")

    -- Insert info about each found threat into database and reject the message
    if ctx.message.has_threat() then
        for threat, path in ctx.message.threats() do
            db_threat_add(datetime, host, ip, mail_from, mail_to, threat.name, threat.type)
        end
        return {action = "reject"}
    end

    -- Insert info about spam into database (if spam score is great than 100) and reject the message
    if ctx.message.spam.score >= 100 then
        db_spam_add(datetime, host, ip, mail_from, mail_to, ctx.message.spam.score)
        return {action = "reject"}
    end

    -- Accept, if the message is not spam and there are no threats found
    return{action = "accept"}
end
