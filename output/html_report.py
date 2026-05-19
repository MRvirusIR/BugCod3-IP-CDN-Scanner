from jinja2 import Template

def save_html(data):

    html = Template("""

<html>

<head>

<title>BugCod3 Scanner</title>

<style>

body{
    background:#071018;
    color:#d1f7ff;
    font-family:Arial;
    padding:20px;
}

h1{
    color:#00e5ff;
}

table{
    width:100%;
    border-collapse:collapse;
    margin-top:20px;
    background:#0b1622;
    border:1px solid #123;
}

th{
    background:#00bcd4;
    color:#fff;
    padding:12px;
    text-align:left;
}

td{
    padding:12px;
    border-bottom:1px solid #13202e;
}

tr:hover{
    background:#102030;
}

.badge{
    padding:6px 12px;
    border-radius:8px;
    color:white;
    font-size:12px;
    font-weight:bold;
}

.card{
    background:#0b1622;
    padding:20px;
    border-radius:12px;
    border:1px solid #123;
    margin-bottom:20px;
}

.stat{
    color:#00e5ff;
    font-weight:bold;
}

</style>

</head>

<body>

<h1>🧠 BugCod3 IP CDN Scanner</h1>

<div class="card">

<p>Total Results:
<span class="stat">{{ data|length }}</span>
</p>

</div>

<table>

<tr>
    <th>Host</th>
    <th>Ports</th>
    <th>Ping</th>
    <th>ISP</th>
    <th>Country</th>
    <th>CDN</th>
</tr>

{% for r in data %}

<tr>

<td>{{ r.host }}</td>

<td>{{ r.open_ports }}</td>

<td>
{% if r.ping != -1 %}
    {{ r.ping }} ms
{% else %}
    N/A
{% endif %}
</td>

<td>{{ r.asn.get("isp","unknown") }}</td>

<td>{{ r.asn.get("country","unknown") }}</td>

<td>
<span class="badge"
style="background: {{ r.cdn.color }}">
{{ r.cdn.cdn }}
</span>
</td>

</tr>

{% endfor %}

</table>

</body>
</html>

""")

    with open("report.html", "w") as f:
        f.write(html.render(data=data))
