class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
         
  has_many :orders
  has_many :line_items
  
  def admin?
    role == "admin"
  end

  def guest?
    role == "guest"
  end
end