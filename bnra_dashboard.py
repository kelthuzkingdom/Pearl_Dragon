import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.express as px
import pandas as pd
import json
import requests

app = dash.Dash(__name__)

app.layout = html.Div([
    html.H1("BNRA Threat Intelligence Dashboard"),
    dcc.Graph(id='threat-intel-graph'),
    dcc.Interval(id='interval-component', interval=5000, n_intervals=0),
    html.Div(id='live-update-text')
])

@app.callback(
    Output('threat-intel-graph', 'figure'),
    [Input('interval-component', 'n_intervals')]
)
def update_graph(n):
    response = requests.get("http://localhost:5000/api/intel/feed")
    data = response.json()
    df = pd.DataFrame(data['intel'])
    fig = px.bar(df, x='timestamp', y='confidence', title='Threat Confidence Over Time')
    return fig

if __name__ == '__main__':
    app.run_server(debug=True)
# Add new tab for intelligence
dcc.Tab(label='Threat Intelligence', children=[
    html.H3('Defensive Intelligence Gathering'),
    html.Div(id='intel-feed'),
    dcc.Interval(id='intel-update', interval=5000)
])
