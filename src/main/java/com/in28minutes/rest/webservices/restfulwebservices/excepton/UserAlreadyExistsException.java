package com.in28minutes.rest.webservices.restfulwebservices.excepton;

public class UserAlreadyExistsException extends RuntimeException{
   public UserAlreadyExistsException(String message){
       super(message);
   }
}
