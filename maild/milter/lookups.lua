local drweb = require "drweb"
local lookup = require 'drweb.lookup'

function get_vals(list)
    local res = ""
    for _, val in ipairs(list) do
        res = res .. val .. ", "
    end
    return res
end

function milter_hook(ctx)
-- SQlite
    -- lookup(return list of values)
    local sqlite_look = lookup.lookup('sqlite@sqlite')
    drweb.notice("SQlite Lookup: " .. get_vals(sqlite_look))
    -- check(return True or False)
    local sqlite_check = lookup.check("adware",'sqlite@sqlite')
    drweb.notice("SQlite Check: " .. tostring(sqlite_check))

-- Redis
    -- lookup(return list of values)
    local redis_look = lookup.lookup('redis@redis')
    drweb.notice("Redis Lookup: " .. get_vals(redis_look))
    -- check(return True or False)
    local redis_check = lookup.check("adware",'redis@redis')
    drweb.notice("Redis Check: " .. tostring(redis_check))

-- Mysql
    -- lookup(return list of values)
    local mysql_look = lookup.lookup('mysql@mysql')
    drweb.notice("Mysql Lookup: " .. get_vals(mysql_look))
    -- check(return True or False)
    local mysql_check = lookup.check("adware",'mysql@mysql')
    drweb.notice("Mysql Check: " .. tostring(mysql_check))


-- Postgre
    -- lookup(return list of values)
    local pq_look = lookup.lookup('pq@psql')
    drweb.notice("Postgre Lookup: " .. get_vals(pq_look))
    -- check(return True or False)
    local pq_check = lookup.check("adware",'pq@psql')
    drweb.notice("Postgre Check: " .. tostring(pq_check))

--File AllMatch
    -- lookup(return list of values)
    local file_allmatch_l = lookup.lookup('allmatch@foo')
    drweb.notice("File AllMatch Lookup: " .. get_vals(file_allmatch_l))
    -- check(return True or False)
    local file_allmatch_c = lookup.check("testing_string",'allmatch@foo')
    drweb.notice("File AllMatch Check: " .. tostring(file_allmatch_c))

--File Mask
    -- lookup(return list of values)
    local file_mask_l = lookup.lookup('mask@beef')
    drweb.notice("File Mask Lookup: " .. get_vals(file_mask_l))
    -- check(return True or False)
    local file_mask_c = lookup.check("fooabcbar",'mask@beef')
    drweb.notice("File Mask Check: " .. tostring(file_mask_c))

--File Regex
    -- lookup(return list of values)
    local file_regex_l = lookup.lookup('regex@bar')
    drweb.notice("File Regex Lookup: " .. get_vals(file_regex_l))
    -- check(return True or False)
    local file_regex_c = lookup.check("8-654-354-237",'regex@bar')
    drweb.notice("File Regex Check: " .. tostring(file_regex_c))

--File Cidr
    -- lookup(return list of values)
    local file_cidr_l = lookup.lookup('cidr@dead')
    drweb.notice("File Cidr Lookup: " .. get_vals(file_cidr_l))
    -- check(return True or False)
    local file_cidr_c = lookup.check("192.168.0.52",'cidr@dead')
    drweb.notice("File Cidr Check: " .. tostring(file_cidr_c))

    return{action = "accept"}
end