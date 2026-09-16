from service import forward


class App:
    def post(self, _path):
        return lambda function: function


app = App()


@app.post("/run")
def route(command):
    return forward(command)
