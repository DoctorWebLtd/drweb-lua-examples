
function milter_hook(ctx)
    -- Check if the message contains viruses, reject if so
    if ctx.message.has_threat({category = {"KnownVirus", "VirusModification", "UnknownVirus", "Adware",
        "Dialer", "Joke", "Riskware", "Hacktool"}}) then
        return {action = 'reject'}
    end
    -- Accept the message otherwise
    return {action = 'accept'}
end
