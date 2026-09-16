from flask import request


@app.patch("/admin/users/<int:user_id>/role")
@admin_required
def update_role(user_id):
    user = User.query.get_or_404(user_id)
    user.role = request.json["role"]
    db.session.commit()
    return {"status": "updated"}
