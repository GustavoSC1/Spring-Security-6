package com.gustavo.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.gustavo.model.Accounts;
import com.gustavo.model.Customer;
import com.gustavo.repository.AccountsRepository;
import com.gustavo.repository.CustomerRepository;

@RestController
public class AccountController {
	
	@Autowired
    private AccountsRepository accountsRepository;
	
	@Autowired
    private CustomerRepository customerRepository;

    @GetMapping("/myAccount")
    public Accounts getAccountDetails(@RequestParam String email) {
		List<Customer> customers = customerRepository.findByEmail(email);
		if (customers != null && !customers.isEmpty()) {
			Accounts accounts = accountsRepository.findByCustomerId(customers.get(0).getId());
			if (accounts != null) {
		    	 return accounts;
			}
		}
		return null;
    }

}
