package ru.kata.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.servise.RoleService;
import ru.kata.spring.boot_security.demo.servise.UserService;

import javax.validation.Valid;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;


@Controller
@RequestMapping(value = "/admin")
public class AdminController {

    private final UserService userService;
    private final RoleService roleService;

    @Autowired
    public AdminController(UserService userService, RoleService roleService) {
        this.userService = userService;
        this.roleService = roleService;
    }

    @GetMapping
    public String printUsers(Model model) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        model.addAttribute("users", userService.getAllUsers());
        model.addAttribute("user", user);
        model.addAttribute("newUser", new User());
        return "/admin";
    }

    @PostMapping("/new")
    public String addNewUser(@Valid @ModelAttribute("newUser") User user, BindingResult result, @RequestParam("roles") ArrayList<Long> roles, Model model) {
        if (result.hasErrors()) {
            // Добавить существующих пользователей и роль в модель для повторного отображения формы
            model.addAttribute("users", userService.getAllUsers());
            model.addAttribute("user", SecurityContextHolder.getContext().getAuthentication().getPrincipal());
            return "/admin";
        }
        user.setRoles(roles.stream().map(roleService::getRole).collect(Collectors.toSet()));
        userService.addUser(user);
        return "redirect:/admin";
    }

    @PutMapping("/update/{id}")
    public String updateUser(@PathVariable("id") long id, @Valid @ModelAttribute("user") User user, BindingResult result, @RequestParam("roles") List<Long> roles) {
        if (result.hasErrors()) {
            // Добавить существующих пользователей и роль в модель для повторного отображения формы
            return "/admin";
        }
        user.setRoles(roles.stream().map(roleService::getRole).collect(Collectors.toSet()));
        userService.updateUser(user);

        return "redirect:/admin";
    }

    @DeleteMapping(value = "/delete/{id}")
    public String delete(@PathVariable("id") long id) {
        userService.deleteUser(id);

        return "redirect:/admin";
    }
}