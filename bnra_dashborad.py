# Add new tab for intelligence
dcc.Tab(label='Threat Intelligence', children=[
    html.H3('Defensive Intelligence Gathering'),
    html.Div(id='intel-feed'),
    dcc.Interval(id='intel-update', interval=5000)
])
