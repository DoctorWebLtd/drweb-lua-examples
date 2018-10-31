
function milter_hook(ctx)
    -- Если сообщение содержит определенные типы угроз то отвергаем его
    -- Check if the message contains threats from specified categories, reject it if so
    if ctx.message.has_threat({category = {"KnownVirus", "VirusModification", "UnknownVirus", "Adware",
        "Dialer", "Joke", "Riskware", "Hacktool"}}) then
        return {action = 'reject'}
    end
    -- В противном случае пропускаем сообщение
    -- Accept the message otherwise
    return {action = 'accept'}
end
