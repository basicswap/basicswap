def page_quickswaps(handler, url_split, post_string):
    swap_client = handler.server.swap_client
    swap_client.checkSystemStatus()
    summary = swap_client.getSummary()

    messages = []
    err_messages = []
    form_data = handler.checkForm(post_string, "quickswaps", messages)
    
    if form_data:
        try:
            pass
        except Exception as e:
            err_messages.append(str(e))

    template = handler.server.env.get_template("quickswaps.html")
    return handler.render_template(
        template,
        {
            "messages": messages,
            "err_messages": err_messages,
            "summary": summary,
        },
    )
