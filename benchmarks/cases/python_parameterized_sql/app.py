def search(request, cursor):
    name = request.args["name"]
    return cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
