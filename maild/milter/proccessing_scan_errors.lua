local drweb = require "drweb"

function milter_hook(ctx)
    -- Iter through all attachments im message
    for mime_part, _ in ctx.message.attachments() do
        -- If attachment is archive trying iterate through files inside of archive
        if mime_part.body.scan_report.archive ~= nil then
            drweb.debug("Archive found: " .. mime_part.name)
            -- Check files inside archive for scan errors
            for _, file in ipairs(mime_part.body.scan_report.item) do
                -- if archive scan has errors send a message copy to admin
                if file.error == "password_protected" or file.error == "unexpected_error" then
                    drweb.debug("Archive error: " .. file.error)
                    return{action = "accept", added_recipients = {'admin@domain.com'}}
                end
            end
        end
    end
    return{action = "accept"}
end


