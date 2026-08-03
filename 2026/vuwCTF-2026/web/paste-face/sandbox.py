from itertools import cycle
import io
from flask import Flask, request, make_response, Response
import pickle

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024

def safe_load(s: bytes):
    return Unpickler(io.BytesIO(s)).load()

allowed_modules = {"random", "math"}
allowed_objects = {("builtins", name) for name in ["int", "str", "list", "set", "dict", "tuple", "getattr"]}
class Unpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module in allowed_modules or (module, name) in allowed_objects:
            if module not in globals():
                mod = __import__(module)
                globals()[module]= mod
                return getattr(mod, name)
            return getattr(globals()[module], name)
        else:
            raise pickle.UnpicklingError(f"{module}.{name} is not allowed to be accessed during unpickling")

def count_letters(s):
    out = {}
    for c in s:
        out[c] = out.get(c,0)+1
    return out
subjects = ["moose", "elk", "mws", "tuolo", "orignal", "los", "alce"]
subject_scores = {subject: count_letters(subject) for subject in subjects}
def evaluate_sentence(sentence, data):
    out = []
    total = 0
    for subject, modifier in zip(subjects, cycle(data)):
        score = 0
        metric = subject_scores[subject]
        for c in sentence.lower():
            score += metric.get(c, 0)
        score *= modifier
        out.append((subject,score))
        total += score
    return [(k,v/total) for k,v in out]

test_sentences = [
    "The quick brown moose jumped over the lazy, grey fox.",
    "Is it 'Elk' or 'Elks'? Who knows!",
    "The word 'moose' came into English from an Algonquian language.",
]
def run_code(code_bytes: bytes):
    data = safe_load(code_bytes)
    if not hasattr(data, "__iter__") or any(not isinstance(modifier, (float, int)) for modifier in data):
        return make_response(f"Data is expected to be an iterable of floats or ints, found {data}", 400)
    scores = {sentence: evaluate_sentence(sentence, data) for sentence in test_sentences}
    return scores

def listify_scores(scores: dict):
    app.logger.error(scores)
    return [scores[sentence] for sentence in test_sentences]

@app.route("/test", methods=["POST"])
def serve_code_runner():
    try:
        results = run_code(request.data)
        if not isinstance(results, Response):
            return listify_scores(results)
    except Exception as e:
        return (f"Exception raised: {repr(e)}", 400)
    return results

if __name__ == "__main__":
    app.run("0.0.0.0", 9998, debug=True)
