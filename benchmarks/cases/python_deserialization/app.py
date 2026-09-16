import pickle


def load_payload(request):
    payload = request.get_json()["payload"]
    return pickle.loads(payload)
