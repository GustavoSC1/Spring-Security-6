package com.gustavo.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.gustavo.model.Contact;

@Repository
public interface ContactRepository extends CrudRepository<Contact, Long> {
	
}