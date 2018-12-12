--
-- Rules for firewall processing in Lua used by Dr.Web Firewall 11.1
--

-- Provided auxiliary modules
local drweb = require "drweb"

function intercept_hook(ctx)
    -- Don't check drweb connections
    if ctx.divert == "output" and ctx.group == "drweb"
    then
        return "pass"
    end

    -- time rules access
    local datetime_rules = {
        worktime = "* 8-18 * * 1-5"
    }
    if ctx.divert == "forward" or ctx.divert == "input" then
        -- allow connections if current time satisfies the condition of the rule (from 8 to 18 hours, from Mon to Fri)
        if rules_processor(datetime_rules.worktime) then
            return "check"
        end
    end

    -- default action
    return "reject"
end


function rules_processor(cron)
    --
    -- Function get rule in cron based format and return true if current datetime satisfies the condition of the rule otherwise return false
    -- Rules based on simplyfied cron format understands absolute values(10 14 * * *) and ranges (0 12-14 * * 1-5)
    --
    -- * * * * *
    -- - - - - -
    -- | | | | |
    -- | | | | ----- Day of week (0 - 6) (Sunday =0)
    -- | | | ------- Month (1 - 12)
    -- | | --------- Day (1 - 31)
    -- | ----------- Hour (0 - 23)
    -- ------------- Minutes (0 - 59)
    --

    local function check(now, rule)
        if rule == "*" then
            return true
        elseif string.find(rule, "-") then
            local thresholds = string.gmatch(rule, '([^-]+)')
            local min_th, max_th = tonumber(thresholds()), tonumber(thresholds())
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
    local now_min, now_hour, now_day, now_month, now_dow = now_stamp(), now_stamp(), now_stamp(), now_stamp(), now_stamp()

    local rule_stamp = string.gmatch(cron, '([^%s]+)')
    local rule_min, rule_hour, rule_day, rule_month, rule_dow = rule_stamp(), rule_stamp(), rule_stamp(), rule_stamp(), rule_stamp()

    if check(now_min, rule_min) and check(now_hour, rule_hour) and check(now_day, rule_day) and check(now_month, rule_month) and check(now_dow, rule_dow) then
        return true
    else
        return false
    end

end

