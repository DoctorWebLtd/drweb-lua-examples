--
-- Rules for network connections processing in Lua used by Dr.Web Firewall 11.1
--

-- Provided auxiliary modules
local drweb = require "drweb"


-- Entry point to check network connections
function intercept_hook(ctx)
    -- 1. Do not check Dr.Web processes' outgoing connections
    if ctx.divert == "output" and ctx.group == "drweb"
    then
        -- Pass the connection
        return "pass"
    end

    -- 2. Other connections should be checked
    -- The rule below allows connection if current time satisfies the specified condition 
    
    -- Condition for time is specified using cron record format (from 8 to 18 hours, from Mon to Fri)
    local datetime_rules = {
        worktime = "* 8-18 * * 1-5"
    }
    if ctx.divert == "forward" or ctx.divert == "input" then
        -- If current time satisfies the condition, connection will be checked for threats 
        if rules_processor(datetime_rules.worktime) then
            return "check"
        end
    end

    -- 3. Reject connection if all conditions above are false
    return "reject"
end


-- Auxiliary function.
-- The function gets condition for date and time in cron record format and returns true if the current time satisfies the condition.
-- Condition should be specified as a string using simplified cron format allows absolute values (10 14 * * *) and ranges (0 12-14 * * 1-5).
-- Fields of the string are as follows:
-- * * * * *
-- | | | | |
-- | | | | ----- Day of week (0 - 6, where 0 is Sunday)
-- | | | ------- Month (1 - 12)
-- | | --------- Day (1 - 31)
-- | ----------- Hours (0 - 23)
-- ------------- Minutes (0 - 59)

function rules_processor(cron)

    local function check(now, rule)
        if rule == "*" then
            return true
        elseif string.find(rule, "-") then
            local thresholds = string.gmatch(rule, '([^-]+)')
            min_th, max_th = tonumber(thresholds()), tonumber(thresholds())
            if tonumber(now) >= min_th and tonumber(now) <= max_th then
                return true
            else
                return false
            end
        elseif rule == now then
            return true
        else
            return false
        end
    end

    local now_stamp = string.gmatch(os.date("%M %H %d %m %w"), '([^%s]+)')
    now_min, now_hour, now_day, now_month, now_dow = now_stamp(), now_stamp(), now_stamp(), now_stamp(), now_stamp()

    local rule_stamp = string.gmatch(cron, '([^%s]+)')
    rule_min, rule_hour, rule_day, rule_month, rule_dow = rule_stamp(), rule_stamp(), rule_stamp(), rule_stamp(), rule_stamp()

    if check(now_min, rule_min) and check(now_hour, rule_hour) and check(now_day, rule_day) and check(now_month, rule_month) and check(now_dow, rule_dow) then
        return true
    else
        return false
    end

end
