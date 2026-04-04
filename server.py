@app.route("/api/auth/verify", methods=["POST"])
def api_verify():
    return jsonify({"error": "Email verification is not enabled"}), 501

@app.route("/api/auth/resend", methods=["POST"])
def api_resend():
    return jsonify({"error": "Email verification is not enabled"}), 501