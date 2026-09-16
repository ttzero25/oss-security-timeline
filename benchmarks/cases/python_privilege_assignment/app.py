from flask import request
from flask_login import login_required


@app.patch("/profile")
@login_required
def update_profile():
    current_user.role = request.json["role"]
    db.session.commit()
    return {"status": "updated"}
