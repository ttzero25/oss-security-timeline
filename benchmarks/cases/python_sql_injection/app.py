def search(request, cursor):
    name = request.args["name"]
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return cursor.execute(query)
