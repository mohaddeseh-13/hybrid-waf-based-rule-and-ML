from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
def backend(path):
    
    """
    WAF تست برای Backend
    """

    return jsonify({
        "status": "OK",
        "backend": "alive",
        "path": path,
        "method": request.method,
        "query_params": request.args.to_dict(),
        "body": request.get_data(as_text=True)
    })


@app.errorhandler(404)
def not_found(e):
    return jsonify({
        "status": "NOT_FOUND",
        "message": "Resource not found on backend"
    }), 404


@app.errorhandler(500)
def internal_error(e):
    return jsonify({
        "status": "ERROR",
        "message": "Internal backend error"
    }), 500


if __name__ == "__main__":
    # فقط برای تست لوکال
    app.run(host="0.0.0.0", port=5001, debug=True)
