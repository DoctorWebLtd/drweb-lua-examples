
function milter_hook(ctx)

    local subject = ""
    -- Устанавливаем переменной modifier, таблицу для осуществления модификаций
    -- Set the variable modifier, the function for implementing the modifications
    local modifier = ctx.modifier

    -- Получаем тему письма из заголовков
    -- Get the subject of the message from the headers
    local headers = ctx.message.header.field
    for i =1, #headers do
       if headers[i].name == "Subject" then
           subject = headers[i].value
       end
    end
    -- Проверяем содержит ли сообщение вирусы и отвергаем письмо если это так
    -- Check if the message contains viruses, reject if so
    if ctx.message.has_threat() then
        return {action = "reject"}
    end
    -- Проверяем письмо на спам и отвергаем если очки спама превышают 100
    -- Reject the message if it is likely spam
    if ctx.message.spam.score > 100 then
        return {action = "reject"}
    end
    -- Если вирусы и спам не найдены, модифицируем тему добавляя к ней наш текст
    -- If viruses and spam are not found, modify the subject by adding our text to it
    modifier.change_header_field("Subject", subject .. " (Mail checked with Dr.Web antivirus)")
    --modifier.change_header_field("Subject", subject .. " (Письмо проверено антивирусом Dr.Web)")

    -- Применяем сделанные модификации и пропускаем сообщение
    -- Apply the modifications and accept the message
    return {action = "accept", modifications = modifier.modifications()}
end
