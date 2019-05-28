local dw = require 'drweb'
local function log(str)
    dw.notice('\x1B[35m' .. str .. '\x1B[0m')
end

-- function print all signature info to drweb log
local function format(signature)
    local str = 'dkim=' .. signature.result.type
    if signature.result.comment ~= '' then
       str = str .. ' (' .. signature.result.comment .. ')'
    end
    if signature.result.key_size then
        str = str .. ' (key size is ' .. signature.result.key_size .. ')'
    end
    str = str .. ' header.i=' .. signature.auid
    str = str .. ' header.s=' .. signature.selector
    str = str .. ' header.hb=' .. signature.sdid
    str = str .. ' header.b=' .. signature.data:sub(0, 10)
    return str
end

function milter_hook(ctx)
    local dkim = ctx.message.dkim
    log('Mail signature count: ' .. #dkim.signature)
    -- Print all signatures found in message
    for _, sign in ipairs(dkim.signature) do
        dw.notice(format(sign))
    end
    -- Accept message if found a valid signature with specified domain
    if ctx.message.dkim.has_valid_signature{domain="*gmail.com"} then
        return {action = "accept"}
    end
    return {action = 'reject'}
end
