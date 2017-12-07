from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, User, Category, Item

engine = create_engine('sqlite:///bikes.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()

# Create Initial user
User1 = User(name="admin",
             email="aaronpastle@gmail.com",
             image_url="https://avatars3.githubusercontent.com/u/4943533?s=460&v=4")
session.add(User1)
session.commit()

# Create first category and samples items
category1 = Category(name="Road Bikes", user_id=1)
session.add(category1)
session.commit()

item1 = Item(user_id=1,
             name="Synapse Carbon 1",
             description="Carbon Road bike built for long haul ride with comfort in mind.",
             price="3499.99",
             manufacturer="Cannondale",
             image_url = "/static/synapse.jpg",
             category=category1)
session.add(item1)
session.commit()

# Second Category and sample item
category2 = Category(name="Mountain Bikes", user_id=1)
session.add(category2)
session.commit()

item2 = Item(user_id = 1,
             name = "Highball",
             description ="29'er Hardtail ready for the cross country mountain trails.",
             price="2999.99",
             manufacturer="Santa Cruz",
             image_url = "/static/highball.jpg",
             category=category2)
session.add(item2)
session.commit()

print "Successful Seeding of data to DB!"
