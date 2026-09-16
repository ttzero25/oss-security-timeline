from worker import Worker


class App:
    def post(self, _path):
        return lambda function: function


app = App()
worker = Worker()


@app.post("/run")
def route(command):
    return worker.execute(command)
