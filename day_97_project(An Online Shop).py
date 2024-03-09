import os

import stripe
from flask import Flask, jsonify, render_template, request, url_for, redirect, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap5
from flask_wtf import FlaskForm
from passlib.handlers import bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SelectField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user

app = Flask(__name__)
login_manager = LoginManager(app)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
Bootstrap5(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///products.db'
db = SQLAlchemy()
db.init_app(app)


#Product TABLE Configuration
class Products(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(250), unique=True, nullable=False)
    img_url = db.Column(db.String(500), nullable=False)
    price = db.Column(db.String(250), nullable=False)
    description = db.Column(db.String(250), nullable=False)
    feature_prod = db.Column(db.String(250), nullable=False)


    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns if getattr(self, column.name) is not None}


# User TABLE Configuration
class User(UserMixin, db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    email = db.Column(db.String(500), nullable=False)
    password = db.Column(db.String(250), nullable=False)

    def get_id(self):
        return self.user_id



# Create a form to register new users
class RegisterForm(FlaskForm):
    username = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")

with app.app_context():
    db.create_all()


@app.route("/")
def home():
    all_items = Products.query.all()
    list_of_items = [product.to_dict() for product in all_items]
    return render_template("index.html", items=list_of_items)


@app.route("/allproducts")
def products():
    all_items = Products.query.all()
    list_of_items = [product.to_dict() for product in all_items]
    return render_template("product.html", items=list_of_items)


@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        # Check if user email is already present in the database.
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if user:
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            username=form.username.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        # This line will authenticate the user with Flask-Login
        login_user(new_user)
        return redirect(url_for("home"))
    return render_template("register.html", form=form, current_user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form['password']
        result = db.session.execute(db.select(User).where(User.username == request.form['username']))
        # Note, email in db is unique so will only have one result.
        user = result.scalar()
        # Email doesn't exist
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        # Password incorrect
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('home'))

    return render_template("login.html", current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


@app.route('/add_to_cart', methods=["POST"])
def add_to_cart():
    product_id = request.form.get('product_id')
    quantity = int(request.form.get('quantity'))

    if 'cart' not in session:
        session['cart'] = {}  # Initialize cart as a dictionary if it doesn't exist

    cart = session['cart']  # Retrieve the cart from session

    # Update the quantity for the given product_id in the cart
    if product_id in cart:
        cart[product_id] += quantity
    else:
        cart[product_id] = quantity

    session['cart'] = cart  # Update the cart in the session

    flash("Item added to cart")
    print(cart)
    return redirect(url_for('view_cart', cart=session.get('cart', {})))


@app.route('/view_cart')
def view_cart():
    cart = session.get('cart', {})  # Retrieve the cart data from the session

    # Fetch product details for items in the cart
    cart_items = []
    basket_total = 0
    for product_id, quantity in cart.items():
        product = Products.query.get(product_id)
        if product:
            # Remove currency symbol and convert price to float
            price = int(product.price.replace('£', ''))  # Assuming the currency symbol is '£'
            item_total = price * quantity
            cart_items.append({
                'product_id': product_id,
                'product_name': product.product_name,
                'img_url': product.img_url,
                'quantity': quantity,
                'price': price,
                'total': item_total
            })
            basket_total += item_total

    return render_template('cart.html', cart=cart_items, total_items=sum(cart.values()), basket_total=basket_total)


@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    if request.method == 'POST':
        # Get the amount to charge from the form data
        amount = request.form['total']

        # Create a charge using the Stripe API
        try:
            stripe.api_key = os.environ.get("Stripe_APIKEY")
            stripe.Charge.create(
                amount=amount,
                currency='gbp',
                source="tok_visa",
                description='Example charge'
            )
            # Handle successful payment
            return render_template('success.html')
        except stripe.error.StripeError as e:
            # Handle errors
            return render_template('error.html', error=str(e))

    # If it's a GET request, render the checkout form
    return render_template('checkout.html', STRIPE_PUBLIC_KEY=os.environ.get("Stripe_Publish"))


@app.route('/Success')
def payment_success():
    for item in session["cart"]:
        product = Products.query.get(item)
        product.stock_volume -= 1
        db.session.commit()
    # newOrder = Order(customer=current_user,
    #     )
    # db.session.add(newOrder)
    # db.session.commit()
    session.pop('cart', None)
    return render_template('Success.html')

if __name__ == '__main__':
    app.run(debug=True)