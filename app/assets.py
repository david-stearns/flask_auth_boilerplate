from flask_assets import Bundle, Environment


def compile_static_assets(app):
    assets = Environment(app)
    Environment.auto_build = True
    Environment.debug = False
    scss = Bundle('src/scss/style.scss', filters='libsass',
                  output='dist/css/style.css')
    assets.register('scss_all', scss)
    if app.config.get('FLASK_ENV') == 'development':
        print('Compiling static assets...')
    scss.build()
