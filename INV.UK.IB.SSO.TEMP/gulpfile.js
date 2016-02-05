var gulp = require('gulp');
var raml2html = require('gulp-raml2html');
var outputFolder = 'Dist';

gulp.task('generateAPI', function () {
    return gulp.src('./Documentation/UsersandAccessManagementAPI.raml')
        .pipe(raml2html())
        .pipe(gulp.dest(outputFolder))

})