
function milter_hook(ctx)

    local subject = ""
    -- Устанавливаем в переменной modifier таблицу для осуществления модификаций
    -- Set modifier variable value to table containing functions for modifications of the message
    local modifier = ctx.modifier

    -- Получаем тему письма из соответствующего заголовка
    -- Get the message' subject from the corresponding header
    local subject = ctx.message.header.value('Subject') or ''
    -- Проверяем, содержит ли сообщение угрозы, и отвергаем его, если это так
    -- Check if the message contains threats, reject it if so
    if ctx.message.has_threat() then
        return {action = "reject"}
    end
    -- Проверяем письмо на спам, и отвергаем его, если число баллов спама превышает 100
    -- Reject the message if it is likely spam (i.e. if spam score exceeds 100)
    if ctx.message.spam.score > 100 then
        return {action = "reject"}
    end
    -- Если угрозы не найдены и сообщение не признано спамом, модифицируем тему письма, добавляя к ней наш текст
    -- If the message is not spam and there are no threats found, modify subject of the message by adding our text
    modifier.change_header_field("Subject", subject .. " (Checked with Dr.Web Anti-Virus)")
    --modifier.change_header_field("Subject", subject .. " (Письмо проверено антивирусом Dr.Web)")

    -- Пропускаем сообщение, применив все сделанные модификации
    -- Accept the message and apply all the modifications
    return {action = "accept"}
end
