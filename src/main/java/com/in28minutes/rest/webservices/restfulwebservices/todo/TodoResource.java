package com.in28minutes.rest.webservices.restfulwebservices.todo;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;

@RestController
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class TodoResource {
    private TodoJpaService todoService;

    public TodoResource(TodoJpaService todoService) {
        this.todoService = todoService;
    }
    @GetMapping("/users/{user}/todos")
    public List<Todo> getTodosByUser(@PathVariable String user){
        return todoService.findByUsername(user);
    }
    @GetMapping("/users/{user}/todos/{id}")
    public Todo getTodoById(@PathVariable String user,@PathVariable int id){
        return  todoService.findById(id);
    }
    @DeleteMapping("/users/{user}/todos/{id}")
    public ResponseEntity<Void> deleteTodoById(@PathVariable String user, @PathVariable int id){
         todoService.deleteById(id);
         return ResponseEntity.noContent().build();
    }
    @PutMapping("/users/{user}/todos/update/{id}")
    public Todo updateTodoById(@PathVariable String user,@PathVariable int id,@RequestBody Todo todo){
        todoService.updateTodo(id,todo);
        return todo;
    }
    @PostMapping("/users/{user}/todos/add")
    public Todo addNewTodo(@PathVariable String user,@RequestBody Todo todo){
        return todoService.addTodo(user, todo.getDescription(), todo.getTargetDate(),todo.isDone());
    }
}
