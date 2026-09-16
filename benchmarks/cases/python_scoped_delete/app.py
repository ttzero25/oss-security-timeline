from flask_login import current_user, login_required


@app.delete("/documents/<int:document_id>")
@login_required
def delete_document(document_id):
    document = Document.query.filter_by(id=document_id, owner_id=current_user.id).first_or_404()
    db.session.delete(document)
    db.session.commit()
    return "", 204
