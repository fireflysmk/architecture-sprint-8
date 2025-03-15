package ru.yandex_practicum.reports_api.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/reports")
public class ReportController {

    @GetMapping
    public Map<String, String> getReports() {
        return Collections.singletonMap("message", "big big report, trust me!");
    }
}