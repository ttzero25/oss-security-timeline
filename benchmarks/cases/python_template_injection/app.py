from flask import render_template_string


def preview(request):
    template = request.form["template"]
    return render_template_string(template)
