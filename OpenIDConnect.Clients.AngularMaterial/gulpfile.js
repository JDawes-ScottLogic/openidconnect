'use strict';

var gulp = require('gulp');
var $ = require('gulp-load-plugins')();
var del = require('del');
var browserify = require('browserify');
var source = require('vinyl-source-stream');

var outputFolder = 'dist';
var contentFolder = 'content';
var sassFiles = contentFolder + '/**/*.scss';
var cssOutputFolder = outputFolder + '/css';
var jsOutputFolder = outputFolder + '/js';
var htmlFiles = contentFolder + '/**/*.html';
var jsMainFile = 'content/app/app.js';
var jsFiles = contentFolder + '/**/*.js';

gulp.task('clean', function () {
    return del([outputFolder]);
});

gulp.task('sass', function(){
    return gulp.src(sassFiles)
        .pipe($.sass({outputStyle: 'compressed'}).on('error', $.sass.logError))
        .pipe($.cssnano())
        .pipe($.flatten())
        .pipe(gulp.dest(cssOutputFolder));
});

gulp.task('sass:watch', function () {
    return gulp.watch(sassFiles, ['sass']);
});

gulp.task('html', function(){
    return gulp.src(htmlFiles)
        .pipe(gulp.dest(outputFolder));
});

gulp.task('html:watch', function(){
    return gulp.watch(htmlFiles, ['html']);
});

gulp.task('js', function(){
    return browserify(jsMainFile)
        .bundle()
        .pipe(source('app.js'))
        .pipe(gulp.dest(jsOutputFolder));
});

gulp.task('js:watch', function(){
    return gulp.watch(jsFiles, ['js']);
});

gulp.task('watch', ['sass:watch', 'js:watch', 'html:watch']);

gulp.task('default', ['sass', 'html', 'js', 'watch'])
