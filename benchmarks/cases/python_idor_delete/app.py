from flask_login import login_required


@app.delete("/documents/<int:document_id>")
@login_required
def delete_document(document_id):
    document = Document.query.get_or_404(document_id)
    db.session.delete(document)
    db.session.commit()
    return "", 204
